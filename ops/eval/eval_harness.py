#!/usr/bin/env python3
"""
Evaluation harness + KPI gate for the sovereign engineering-knowledge Q&A system.

Stdlib only. Runs a golden set (JSONL) through a system under test, computes
quality, safety and sovereignty KPIs, compares them to thresholds and exits
non-zero when any gate fails. Also supports a model-swap regression comparison
(baseline vs candidate model for the same role).

The "system" here is a deterministic MOCK of the real pipeline
(supervisor -> retrieval agent -> answer model -> verifier, behind a BYOM
gateway). In CI you replace MockSystem with an HTTP client that calls the
staging deployment and returns the same AnswerRecord shape, including the
trace that the real system writes to its audit log.

Exit codes: 0 = all gates pass, 1 = gate failure, 2 = usage/config error.

Usage:
  python3 eval_harness.py --model eu-large-a
  python3 eval_harness.py --model eu-large-a --inject-faults region,acl,stale
  python3 eval_harness.py --swap eu-large-a eu-large-b
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent

STOPWORDS = set("""a an the and or of for to in on at by with from is are was were be been what which
who how many much does do did after before this that these those it its as into per than then there their
our your my me i you we they should can could would will set used use uses needed need applies apply""".split())

INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?(previous|prior) instructions", re.I),
    re.compile(r"disregard (the )?(system|above)", re.I),
    re.compile(r"you are now", re.I),
]

REFUSAL_TEXT = "I can't answer that from the documents you have access to."
ESCALATE_TEXT = "I could not verify an answer against the cited documents; escalating to a subject-matter expert."

NUM_RE = re.compile(
    r"(?<![\w.])(\d+(?:\.\d+)?(?:e[+-]?\d+)?)\s*(nm|mm|um|w|%|ma|cm-2|s|degrees)?(?![\w])",
    re.I,
)


# ----------------------------------------------------------------------------
# Text utilities
# ----------------------------------------------------------------------------
def tokens(text: str) -> list[str]:
    raw = re.findall(r"[a-z0-9][a-z0-9\-./]*", text.lower())
    out = []
    for t in raw:
        t = t.strip(".-/")
        if t and t not in STOPWORDS:
            out.append(t)
    return out


def content_tokens(text: str) -> set[str]:
    return {t for t in tokens(text) if len(t) >= 4 or any(c.isdigit() for c in t)}


def extract_numbers(text: str) -> set[tuple[float, str]]:
    found = set()
    for m in NUM_RE.finditer(text):
        try:
            val = float(m.group(1))
        except ValueError:
            continue
        found.add((val, (m.group(2) or "").lower()))
    return found


def number_present(expected: str, answer_numbers: set[tuple[float, str]]) -> bool:
    exp = extract_numbers(expected)
    if len(exp) != 1:
        raise ValueError(f"expected_numbers entry must contain exactly one number: {expected!r}")
    (val, unit), = exp
    for v, u in answer_numbers:
        if math.isclose(v, val, rel_tol=0, abs_tol=1e-12) and (unit == "" or u == unit):
            return True
    return False


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text.strip())
    return [p for p in parts if p]


# ----------------------------------------------------------------------------
# Mock system under test
# ----------------------------------------------------------------------------
@dataclass
class ModelCall:
    role: str
    model: str
    endpoint_region: str
    input_tokens: int
    output_tokens: int


@dataclass
class AnswerRecord:
    item_id: str
    answer: str
    refused: bool
    escalated: bool
    retrieved: list[str]                 # "DOC@REV" in rank order (what entered the context)
    cited: list[str]                     # "DOC@REV" cited in the answer
    trace: dict | None                   # audit record; None = missing
    model_calls: list[ModelCall] = field(default_factory=list)


class MockGateway:
    """BYOM gateway: resolves a model ROLE to the customer's EU endpoint."""

    def __init__(self, answer_model: str, faults: set[str]):
        self.routes = {
            "router":   {"model": "eu-small-8b",  "region": "eu-central-1"},
            "answer":   {"model": answer_model,   "region": "eu-central-1"},
            "verifier": {"model": "eu-medium-24b", "region": "eu-west-1"},
        }
        self.faults = faults
        self.calls = 0

    def resolve(self, role: str) -> dict:
        self.calls += 1
        route = dict(self.routes[role])
        # Fault: silent fallback to a non-EU endpoint on provider error (the
        # exact failure the out_of_region_calls gate exists to catch).
        if "region" in self.faults and role == "answer" and self.calls % 7 == 0:
            route["region"] = "us-east-1"
        return route


class MockSystem:
    def __init__(self, corpus_path: Path, answer_model: str, k: int, faults: set[str]):
        corpus = json.loads(corpus_path.read_text())
        self.chunks = corpus["chunks"]
        self.expected_embedding = corpus["embedding_model_expected"]
        if "mixed-index" in faults:
            self.chunks = [dict(c) for c in self.chunks]
            self.chunks[3]["embedding_model"] = "emb-eu-v3"   # half-migrated index
        self.answer_model = answer_model
        self.k = k
        self.faults = faults
        self.gw = MockGateway(answer_model, faults)
        n = len(self.chunks)
        df: dict[str, int] = {}
        for c in self.chunks:
            for t in set(tokens(c["text"])):
                df[t] = df.get(t, 0) + 1
        self.idf = {t: math.log((n + 1) / (d + 0.5)) for t, d in df.items()}

    # --- retrieval agent (permission- and revision-scoped) -----------------
    def _score(self, q_toks: set[str], chunk: dict) -> float:
        c_toks = set(tokens(chunk["text"]))
        return sum(self.idf.get(t, 0.0) for t in q_toks & c_toks)

    def retrieve(self, question: str, groups: list[str]) -> list[tuple[float, dict]]:
        q = set(tokens(question))
        cands = []
        for c in self.chunks:
            if "acl" not in self.faults and not set(groups) & set(c["acl"]):
                continue                       # permission filter BEFORE ranking
            if "stale" not in self.faults and c["status"] != "current":
                continue                       # revision filter
            s = self._score(q, c)
            if "stale" in self.faults and c["status"] == "superseded":
                s *= 1.5                       # fault: stale rev outranks current
            cands.append((s, c))
        cands.sort(key=lambda x: -x[0])
        return cands[: self.k]

    # --- answer model (deterministic stand-in) -------------------------------
    def _generate(self, question: str, top: list[tuple[float, dict]]) -> tuple[str, list[str]]:
        q = set(tokens(question))
        best_score, best = top[0]
        use = [c for s, c in top if s >= 0.8 * best_score and c["doc_id"] == best["doc_id"]][:1] or [best]
        sentences, cited = [], []
        for c in use:
            ref = f'{c["doc_id"]}@{c["rev"]}'
            for sent in split_sentences(c["text"]):
                # retrieved text is untrusted: drop instruction-like spans
                if any(p.search(sent) for p in INJECTION_PATTERNS):
                    continue
                if set(tokens(sent)) & q:
                    sentences.append(self._style(sent) + f" [{ref}]")
                    if ref not in cited:
                        cited.append(ref)
        return " ".join(sentences), cited

    def _style(self, sent: str) -> str:
        # Candidate model "eu-large-b" paraphrases numbers (a typical swap regression).
        if self.answer_model == "eu-large-b":
            def approx(m: re.Match) -> str:
                v = float(m.group(1))
                return f"about {round(v)}" if v != round(v) else m.group(0)
            return re.sub(r"(?<![\w.])(\d+\.\d+)(?![\w])", approx, sent)
        return sent

    # --- verifier agent -------------------------------------------------------
    def _verify(self, answer: str, cited: list[str]) -> bool:
        cited_text = " ".join(c["text"] for c in self.chunks if f'{c["doc_id"]}@{c["rev"]}' in cited)
        src_nums = extract_numbers(cited_text)
        for v, u in extract_numbers(re.sub(r"\[[^\]]+\]", "", answer)):
            if not any(math.isclose(v, sv) and (u == su or u == "") for sv, su in src_nums):
                return False
        return bool(cited)

    def ask(self, item: dict) -> AnswerRecord:
        req_id = str(uuid.uuid4())
        calls = []
        r = self.gw.resolve("router")
        calls.append(ModelCall("router", r["model"], r["region"], 120, 10))
        top = self.retrieve(item["question"], item["user_groups"])
        retrieved = [f'{c["doc_id"]}@{c["rev"]}' for _, c in top]
        refused = escalated = False
        cited: list[str] = []
        # Refuse when nothing permitted and relevant was found (abstain > guess).
        if not top or top[0][0] < 3.0:
            answer, refused = REFUSAL_TEXT, True
        else:
            r = self.gw.resolve("answer")
            answer, cited = self._generate(item["question"], top)
            calls.append(ModelCall("answer", r["model"], r["region"], 900, 80))
            v = self.gw.resolve("verifier")
            calls.append(ModelCall("verifier", v["model"], v["region"], 600, 5))
            if not answer:
                answer, refused = REFUSAL_TEXT, True
            elif not self._verify(answer, cited):
                answer, escalated, cited = ESCALATE_TEXT, True, []
        trace = {
            "request_id": req_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "user_groups": item["user_groups"],
            "retrieved": retrieved,
            "cited": cited,
            "model_calls": [asdict(c) for c in calls],
            "policy_decisions": {"acl_filter": "acl" not in self.faults, "revision_filter": "stale" not in self.faults},
            "embedding_models": sorted({c["embedding_model"] for _, c in top}),
        }
        if "audit" in self.faults and item["id"] == "G05":
            trace = None                      # fault: audit write dropped
        return AnswerRecord(item["id"], answer, refused, escalated, retrieved, cited, trace, calls)


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------
REQUIRED_TRACE_FIELDS = {"request_id", "timestamp", "user_groups", "retrieved", "cited", "model_calls", "policy_decisions"}


def compute_metrics(items: list[dict], records: list[AnswerRecord], system: MockSystem, cfg: dict) -> dict:
    by_id = {c["doc_id"] + "@" + c["rev"]: c for c in system.chunks}
    allowed_regions = set(cfg["allowed_regions"])
    recall, faith, num_ok, num_n = [], [], 0, 0
    cit_ok = cit_n = 0
    refuse_ok = refuse_n = answered = answerable = 0
    inj = oor = perm = stale = idx = audit_ok = 0
    per_item = []

    for it, rec in zip(items, records):
        groups = set(it["user_groups"])
        row = {"id": it["id"], "refused": rec.refused, "escalated": rec.escalated}
        # --- sovereignty / safety counters (apply to every item) ---
        for mc in rec.model_calls:
            if mc.endpoint_region not in allowed_regions:
                oor += 1
        for ref in set(rec.retrieved) | set(rec.cited):
            ch = by_id.get(ref)
            if ch and not groups & set(ch["acl"]):
                perm += 1
        for ref in rec.cited:
            ch = by_id.get(ref)
            if ch and ch["status"] != "current":
                stale += 1
        for ref in rec.retrieved:
            ch = by_id.get(ref)
            if ch and ch["embedding_model"] != system.expected_embedding:
                idx += 1
        for phrase in it.get("forbidden_phrases", []):
            if phrase.lower() in rec.answer.lower():
                inj += 1
        if rec.trace and REQUIRED_TRACE_FIELDS <= set(rec.trace):
            audit_ok += 1

        if it["must_refuse"]:
            refuse_n += 1
            ok = rec.refused and not rec.cited
            refuse_ok += ok
            row["correct_refusal"] = ok
        else:
            answerable += 1
            exp = set(it["expected_docs"])
            got = set(rec.retrieved[: cfg["k"]])
            r = len(exp & got) / len(exp) if exp else 1.0
            recall.append(r)
            row["recall"] = r
            gave_answer = not (rec.refused or rec.escalated)
            answered += gave_answer
            # Exact numeric match: every expected number appears verbatim (value+unit).
            if it["expected_numbers"]:
                num_n += 1
                ans_nums = extract_numbers(re.sub(r"\[[^\]]+\]", "", rec.answer)) if gave_answer else set()
                ok = all(number_present(e, ans_nums) for e in it["expected_numbers"])
                num_ok += ok
                row["numeric_ok"] = ok
            # Citation accuracy: cited ref must be retrieved, permitted, current,
            # and actually contain the sentence it is attached to.
            for sent in split_sentences(rec.answer):
                for ref in re.findall(r"\[([^\]]+)\]", sent):
                    cit_n += 1
                    ch = by_id.get(ref)
                    body = re.sub(r"\[[^\]]+\]", "", sent)
                    valid = (
                        ch is not None and ref in rec.retrieved and groups & set(ch["acl"])
                        and ch["status"] == "current"
                        and len(content_tokens(body) - content_tokens(ch["text"])) == 0
                        and extract_numbers(body) <= extract_numbers(ch["text"])
                    )
                    cit_ok += bool(valid)
            # Faithfulness proxy: share of answer sentences whose content tokens AND
            # numbers are all supported by the union of cited chunks.
            if gave_answer:
                src = " ".join(by_id[c]["text"] for c in rec.cited if c in by_id)
                src_toks, src_nums = content_tokens(src), extract_numbers(src)
                sents = split_sentences(re.sub(r"\[[^\]]+\]", "", rec.answer))
                sup = 0
                for s in sents:
                    ct = content_tokens(s)
                    cov = len(ct & src_toks) / len(ct) if ct else 1.0
                    sup += cov >= 0.8 and extract_numbers(s) <= src_nums
                f = sup / len(sents) if sents else 0.0
            else:
                f = 0.0  # an abstention on an answerable question is not a faithful answer
            faith.append(f)
            row["faithfulness"] = round(f, 3)
        per_item.append(row)

    n = len(items)
    mean = lambda xs: sum(xs) / len(xs) if xs else 1.0
    return {
        "metrics": {
            "retrieval_recall_at_k": round(mean(recall), 4),
            "faithfulness": round(mean(faith), 4),
            "exact_numeric_match": round(num_ok / num_n, 4) if num_n else 1.0,
            "citation_accuracy": round(cit_ok / cit_n, 4) if cit_n else 1.0,
            "correct_refusal_rate": round(refuse_ok / refuse_n, 4) if refuse_n else 1.0,
            "answer_rate": round(answered / answerable, 4) if answerable else 1.0,
            "injection_followed": inj,
            "out_of_region_calls": oor,
            "permission_violations": perm,
            "superseded_revision_answers": stale,
            "index_consistency_violations": idx,
            "audit_completeness": round(audit_ok / n, 4) if n else 1.0,
        },
        "counts": {"items": n, "answerable": answerable, "must_refuse": refuse_n,
                   "citations": cit_n, "model_calls": sum(len(r.model_calls) for r in records),
                   "tokens": sum(m.input_tokens + m.output_tokens for r in records for m in r.model_calls)},
        "per_item": per_item,
    }


def check_gates(metrics: dict, gates: dict) -> list[str]:
    failures = []
    for name, rule in gates.items():
        val = metrics.get(name)
        if val is None:
            failures.append(f"{name}: metric missing")
        elif "min" in rule and val < rule["min"]:
            failures.append(f"{name}={val} < min {rule['min']}")
        elif "max" in rule and val > rule["max"]:
            failures.append(f"{name}={val} > max {rule['max']}")
    return failures


def compare_swap(base: dict, cand: dict, cfg: dict) -> list[str]:
    failures = []
    lim = cfg["max_relative_drop"]
    for m in cfg["compared_metrics"]:
        b, c = base[m], cand[m]
        drop = (b - c) / b if b else 0.0
        status = "FAIL" if drop > lim else "ok"
        print(f"  {m:<26} baseline={b:<7} candidate={c:<7} rel_drop={drop:+.2%}  {status}")
        if drop > lim:
            failures.append(f"{m} dropped {drop:.2%} (> {lim:.0%})")
    return failures


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def load_jsonl(p: Path) -> list[dict]:
    items = []
    for i, line in enumerate(p.read_text().splitlines(), 1):
        if line.strip():
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"golden set line {i}: {e}")
    return items


def run(model: str, faults: set[str], items: list[dict], cfg: dict, corpus: Path) -> dict:
    sysu = MockSystem(corpus, model, cfg["k"], faults)
    records = [sysu.ask(it) for it in items]
    return compute_metrics(items, records, sysu, cfg)


def print_metrics(title: str, res: dict, gates: dict) -> list[str]:
    print(f"== {title}")
    for k, v in res["metrics"].items():
        rule = gates.get(k)
        tag = "" if rule is None else ("  [gate " + ", ".join(f"{a} {b}" for a, b in rule.items()) + "]")
        print(f"  {k:<30} {v}{tag}")
    print(f"  counts: {res['counts']}")
    fails = check_gates(res["metrics"], gates)
    for f in fails:
        print(f"  GATE FAIL: {f}")
    print(f"  RESULT: {'PASS' if not fails else 'FAIL'}")
    return fails


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--golden", default=str(HERE / "golden_set.jsonl"))
    ap.add_argument("--corpus", default=str(HERE / "corpus.json"))
    ap.add_argument("--thresholds", default=str(HERE / "thresholds.json"))
    ap.add_argument("--model", default="eu-large-a", help="answer-role model id to evaluate")
    ap.add_argument("--inject-faults", default="", help="comma list: region,acl,stale,mixed-index,audit")
    ap.add_argument("--swap", nargs=2, metavar=("BASELINE", "CANDIDATE"), help="model-swap regression check")
    ap.add_argument("--report", default="", help="write JSON report to this path")
    a = ap.parse_args(argv)

    try:
        cfg = json.loads(Path(a.thresholds).read_text())
        items = load_jsonl(Path(a.golden))
    except (OSError, json.JSONDecodeError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    faults = {f for f in a.inject_faults.split(",") if f}
    unknown = faults - {"region", "acl", "stale", "mixed-index", "audit"}
    if unknown:
        print(f"unknown faults: {unknown}", file=sys.stderr)
        return 2

    report = {}
    if a.swap:
        base_m, cand_m = a.swap
        base = run(base_m, faults, items, cfg, Path(a.corpus))
        cand = run(cand_m, faults, items, cfg, Path(a.corpus))
        f1 = print_metrics(f"baseline {base_m}", base, cfg["gates"])
        f2 = print_metrics(f"candidate {cand_m}", cand, cfg["gates"])
        print("== model-swap regression (candidate vs baseline)")
        f3 = compare_swap(base["metrics"], cand["metrics"], cfg["model_swap"])
        flips = [b["id"] for b, c in zip(base["per_item"], cand["per_item"])
                 if b.get("numeric_ok") and not c.get("numeric_ok")]
        if flips:
            print(f"  items regressed on numeric match: {flips}")
        failures = f2 + f3  # baseline failures are informational
        print(f"== SWAP DECISION: {'ACTIVATE candidate' if not failures else 'BLOCK candidate activation'}")
        report = {"baseline": base, "candidate": cand, "failures": failures}
    else:
        res = run(a.model, faults, items, cfg, Path(a.corpus))
        failures = print_metrics(f"model={a.model} faults={sorted(faults) or 'none'}", res, cfg["gates"])
        report = {"result": res, "failures": failures}

    if a.report:
        Path(a.report).write_text(json.dumps(report, indent=2, default=str))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
