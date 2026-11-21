"""
sovereign_agents.py - Supervisor + specialists + verifier for an EU sovereign
engineering-knowledge Q&A assistant (semiconductor fab: SOPs, spec tables, 8D reports).

Written against the LangGraph 1.x API. If `langgraph` is importable it is used; otherwise
the dependency-free shim `minigraph` (same names/semantics for the subset used) runs it.

Graph:
    START -> supervisor --(Command goto)--> procedure | spec | incident | approval | finalize
    procedure/spec/incident -> verifier --(pass)--> finalize -> END
                                        --(fail, LLM draft, attempts left)--> incident (retry w/ feedback)
                                        --(fail)--> finalize ("Not found in approved documents.")
    approval: interrupt() -> human decision -> execute_action (idempotent) | finalize

Model use follows "route by difficulty": router role (small/cheap) only for intent;
NO model for procedure (verbatim SOP) or spec (exact table values); reasoning role only
for incident synthesis. Every model call goes through the BYOM gateway by ROLE.

Bounded loops: MAX_STEPS in state + LangGraph recursion_limit + MAX_VERIFY_ATTEMPTS.
"""
from __future__ import annotations

import hashlib
import json
import math
import operator
import re
import uuid
from collections import Counter
from typing import Annotated, Literal, Optional, TypedDict

try:  # --- real LangGraph 1.x -------------------------------------------------
    from langgraph.graph import StateGraph, START, END
    from langgraph.types import Command, interrupt
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.errors import GraphRecursionError
    BACKEND = "langgraph"
except ImportError:  # --- dependency-free shim ----------------------------------
    from minigraph import StateGraph, START, END, Command, interrupt, InMemorySaver, GraphRecursionError
    BACKEND = "minigraph"

from byom_gateway_v2 import ChatRequest, Needs, SearchOnlyMode, build_demo_gateway

TENANT = "fab-eu"
MAX_STEPS = 10
MAX_VERIFY_ATTEMPTS = 2
NOT_FOUND = "Not found in approved documents."

# =============================================================================
# Mock approved corpus (stands in for OpenSearch/Vertex Vector Search + DMS links)
# =============================================================================
SOPS = [
    {"id": "SOP-ETCH-014#6", "doc": "SOP-ETCH-014 rev C", "safety_critical": True,
     "link": "https://dms.fab.example/SOP-ETCH-014/revC#step6",
     "text": "Step 6 (SAFETY-CRITICAL): Before opening the chamber lid on ETCH-2, vent the chamber to "
             "atmosphere, confirm gauge PG-2 reads 760 Torr, and apply lockout/tagout to the RF generator."},
    {"id": "SOP-CMP-007#3", "doc": "SOP-CMP-007 rev F", "safety_critical": False,
     "link": "https://dms.fab.example/SOP-CMP-007/revF#step3",
     "text": "Step 3: Condition the CMP pad for 30 seconds at 5 lbf downforce before the first wafer of each lot."},
]
SPEC_ROWS = [
    {"id": "SPEC-RTP-T3#1", "doc": "SPEC-RTP-002", "table": "T3", "rev": "D", "param": "Anneal temperature",
     "aliases": ["anneal temperature", "anneal temp", "anneal"], "tool": "RTP-3", "value": "350 ± 5 °C",
     "link": "https://dms.fab.example/SPEC-RTP-002/revD#T3"},
    {"id": "SPEC-RTP-T3#2", "doc": "SPEC-RTP-002", "table": "T3", "rev": "D", "param": "Ramp rate",
     "aliases": ["ramp rate", "ramp"], "tool": "RTP-3", "value": "50 °C/s max",
     "link": "https://dms.fab.example/SPEC-RTP-002/revD#T3"},
    {"id": "SPEC-ETCH-T1#4", "doc": "SPEC-ETCH-011", "table": "T1", "rev": "B", "param": "Chamber base pressure",
     "aliases": ["base pressure", "chamber pressure"], "tool": "ETCH-2", "value": "0.8 mTorr",
     "link": "https://dms.fab.example/SPEC-ETCH-011/revB#T1"},
]
for r in SPEC_ROWS:  # the passage text a spec answer is verified against
    r["text"] = f"{r['doc']} table {r['table']} rev {r['rev']}: {r['param']} | {r['tool']} | {r['value']}"
INCIDENTS = [
    {"id": "INC-2025-117", "link": "https://qms.fab.example/8D/INC-2025-117",
     "text": "Wafer breakage on RTP-3 after the ramp rate was set to 75 °C/s. Root cause: recipe override "
             "without engineering approval. Corrective action: recipe lock and dual sign-off."},
    {"id": "INC-2026-031", "link": "https://qms.fab.example/8D/INC-2026-031",
     "text": "Particle excursion on ETCH-2 after chamber wet clean. Root cause: incomplete seasoning, 12 "
             "wafers instead of 25. Containment: 100% inspection of affected lots."},
    {"id": "INC-2026-044", "link": "https://qms.fab.example/8D/INC-2026-044",
     "text": "RF arcing on ETCH-2 traced to a worn electrode. Corrective action: electrode replacement "
             "interval reduced to 900 RF hours."},
]

_WORD = re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*")
_NUM = re.compile(r"\d+(?:[.,]\d+)*")
_STOP = set("the a an of on in to for and or is was were be by with at after before from what which have "
            "we seen did it this that how do i my our as are its".split())


def _tokens(s: str) -> list[str]:
    return [w for w in _WORD.findall(s.lower()) if w not in _STOP]


def _cosine(a: str, b: str) -> float:
    ca, cb = Counter(_tokens(a)), Counter(_tokens(b))
    dot = sum(ca[w] * cb[w] for w in ca)
    na, nb = math.sqrt(sum(v * v for v in ca.values())), math.sqrt(sum(v * v for v in cb.values()))
    return dot / (na * nb) if na and nb else 0.0


def search(corpus: list[dict], query: str, k: int = 2, min_score: float = 0.25) -> list[dict]:
    """Stand-in for hybrid (BM25 + vector) retrieval. Also the lexical fallback used
    when the embedding model is unavailable (gateway -> SearchOnlyMode)."""
    scored = sorted(((round(_cosine(query, d["text"]), 3), d) for d in corpus), key=lambda x: -x[0])
    return [{**d, "score": s} for s, d in scored[:k] if s >= min_score]


# =============================================================================
# Mock model behaviour behind the gateway (what the tenant's models would return)
# =============================================================================
def make_responder(hallucinate_times: int = 0):
    """router: keyword intent classifier. reasoning: extractive synthesis with citations.
    hallucinate_times: first N reasoning calls corrupt a number (to exercise the verifier)."""
    left = {"n": hallucinate_times}

    def responder(spec, req):
        q = req.messages[-1]["content"]
        if req.system.startswith("ROLE:router"):
            ql = q.lower()
            if re.search(r"\b(open|create|raise|file)\b.*\b(capa|ticket|work order)\b", ql):
                return "action"
            if re.search(r"incident|8d|root cause|seen|happened", ql):
                return "incident"
            if re.search(r"procedure|sop|steps|how do", ql):
                return "procedure"
            if re.search(r"spec|limit|temperature|pressure|rate|value", ql):
                return "spec"
            return "unknown"
        # reasoning: extractive - one cited line per source sentence
        lines = []
        for pid, ptext in re.findall(r"\[(\S+)\] (.+)", q):
            for sent in re.split(r"(?<=\.)\s", ptext):
                if left["n"] > 0:
                    sent = sent.replace("75", "80")   # a plausible but WRONG number
                lines.append(f"{sent} [{pid}]")
        if left["n"] > 0:
            left["n"] -= 1
        return "\n".join(lines)

    return responder


# =============================================================================
# State
# =============================================================================
class QAState(TypedDict, total=False):
    question: str
    thread_id: str
    intent: str
    passages: list[dict]                 # retrieved, approved passages {id, text, link, ...}
    draft: list[dict]                    # [{"text", "cites": [ids], "verbatim": bool}]
    source: str                          # which specialist produced the draft
    mode: str                            # normal | search_only
    verdict: dict
    verify_attempts: int
    feedback: str
    steps: int
    proposal: dict
    action_result: dict
    answer: str
    trace: Annotated[list[str], operator.add]   # reducer: appended, not overwritten


GATEWAY, _MOCK = build_demo_gateway(responder=make_responder())
ACTION_LOG: dict[str, dict] = {}   # stands in for the CAPA system (idempotency-keyed)


def _bump(state: QAState) -> int:
    return state.get("steps", 0) + 1


# =============================================================================
# Nodes
# =============================================================================
def supervisor(state: QAState) -> Command[Literal["procedure", "spec", "incident", "approval", "finalize"]]:
    steps = _bump(state)
    if steps > MAX_STEPS:
        return Command(goto="finalize", update={"steps": steps, "trace": ["supervisor:step_limit"]})
    try:
        intent = GATEWAY.chat(TENANT, "router", ChatRequest(
            system="ROLE:router Classify the engineering question as one of: "
                   "procedure|spec|incident|action|unknown. Reply with the label only.",
            messages=[{"role": "user", "content": state["question"]}], max_tokens=5),
            task_id=state.get("thread_id", "-")).text.strip()
    except SearchOnlyMode:
        intent = "incident"   # router down: similarity search is the safest generic path
    goto = {"procedure": "procedure", "spec": "spec", "incident": "incident",
            "action": "approval"}.get(intent, "finalize")
    # Reset per-question fields: a thread (conversation) is reused across questions.
    return Command(goto=goto, update={"intent": intent, "steps": steps, "verify_attempts": 0,
                                      "mode": "normal", "feedback": "", "verdict": {}, "draft": [],
                                      "passages": [], "trace": [f"supervisor:{intent}"]})


def procedure_agent(state: QAState) -> dict:
    """SOP wording + link, NO paraphrase. No model call at all."""
    hits = search(SOPS, state["question"], k=1)
    draft = [{"text": h["text"], "cites": [h["id"]], "verbatim": True} for h in hits]
    return {"passages": hits, "draft": draft, "source": "procedure", "steps": _bump(state),
            "trace": [f"procedure:{[h['id'] for h in hits]}"]}


def spec_agent(state: QAState) -> dict:
    """Exact values from the table row; the model never produces a number."""
    ql = state["question"].lower()
    rows = [r for r in SPEC_ROWS if r["tool"].lower() in ql and any(a in ql for a in r["aliases"])]
    draft = [{"text": f"{r['param']} for {r['tool']}: {r['value']} ({r['doc']} table {r['table']} rev {r['rev']}).",
              "cites": [r["id"]], "verbatim": False} for r in rows[:1]]
    return {"passages": rows[:1], "draft": draft, "source": "spec", "steps": _bump(state),
            "trace": [f"spec:{[r['id'] for r in rows[:1]]}"]}


def incident_agent(state: QAState) -> dict:
    hits = search(INCIDENTS, state["question"], k=2)
    if not hits:
        return {"passages": [], "draft": [], "source": "incident", "steps": _bump(state), "trace": ["incident:no_hits"]}
    context = "\n".join(f"[{h['id']}] {h['text']}" for h in hits)
    try:
        out = GATEWAY.chat(TENANT, "reasoning", ChatRequest(
            system="ROLE:reasoning Summarise ONLY from the passages. One sentence per line, each ending "
                   "with its [ID]. Copy numbers exactly. " + state.get("feedback", ""),
            messages=[{"role": "user", "content": context}], needs=Needs(min_context=2_000)),
            task_id=state.get("thread_id", "-")).text
        draft = [{"text": m.group(1).strip(), "cites": [m.group(2)], "verbatim": False}
                 for m in re.finditer(r"(.+?)\s*\[(\S+?)\]\s*$", out, re.M)]
        mode = "normal"
    except SearchOnlyMode as e:
        # Graceful degradation: verbatim passages, no generation.
        draft = [{"text": h["text"], "cites": [h["id"]], "verbatim": True} for h in hits]
        mode = "search_only"
    return {"passages": hits, "draft": draft, "source": "incident", "mode": mode, "steps": _bump(state),
            "trace": [f"incident:{mode}:{[h['id'] for h in hits]}"]}


def verify(draft: list[dict], passages: list[dict], overlap_min: float = 0.6) -> dict:
    """Deterministic checks. Every sentence must (1) cite a retrieved passage, (2) be a
    verbatim substring if marked verbatim, (3) have >= overlap_min of its content words in
    the cited passage (lexical grounding proxy - add an NLI/LLM judge from a different model
    family in production), (4) contain only numbers that appear token-for-token,
    character-for-character in the cited passage."""
    by_id = {p["id"]: p for p in passages}
    problems = []
    if not draft:
        return {"ok": False, "problems": ["empty draft"]}
    for i, s in enumerate(draft):
        cited = [by_id[c] for c in s["cites"] if c in by_id]
        if not cited:
            problems.append(f"s{i}: no valid citation"); continue
        src = " ".join(p["text"] for p in cited)
        if s.get("verbatim"):
            if s["text"] not in src:
                problems.append(f"s{i}: verbatim quote altered")
            continue
        words = _tokens(s["text"])
        src_words = set(_tokens(src))
        if words and sum(w in src_words for w in words) / len(words) < overlap_min:
            problems.append(f"s{i}: low grounding")
        src_nums = set(_NUM.findall(src))
        bad = [n for n in _NUM.findall(s["text"]) if n not in src_nums]
        if bad:
            problems.append(f"s{i}: numbers not in source {bad}")
    return {"ok": not problems, "problems": problems}


def verifier(state: QAState) -> Command[Literal["incident", "finalize"]]:
    v = verify(state.get("draft", []), state.get("passages", []))
    attempts = state.get("verify_attempts", 0) + 1
    upd = {"verdict": v, "verify_attempts": attempts, "steps": _bump(state),
           "trace": [f"verifier:{'pass' if v['ok'] else 'fail'}:{attempts}"]}
    if v["ok"]:
        return Command(goto="finalize", update=upd)
    # Only LLM-generated drafts get a retry; deterministic agents failing = genuinely not found.
    if state.get("source") == "incident" and state.get("mode") == "normal" and attempts < MAX_VERIFY_ATTEMPTS:
        upd["feedback"] = "Previous draft failed verification: " + "; ".join(v["problems"])
        return Command(goto="incident", update=upd)
    return Command(goto="finalize", update=upd)


def approval(state: QAState) -> Command[Literal["execute_action", "finalize"]]:
    """Human-in-the-loop for ANY write action. Code before interrupt() re-runs on resume,
    so it must be deterministic and side-effect free (it is: builds a proposal only)."""
    hits = search(INCIDENTS, state["question"], k=1)
    proposal = {"action": "create_capa", "related": [h["id"] for h in hits],
                "title": state["question"][:120], "requested_by_thread": state.get("thread_id")}
    decision = interrupt({"type": "approval_required", "proposal": proposal,
                          "message": "Approve creating this CAPA in the QMS?"})
    if isinstance(decision, dict) and decision.get("approved") is True:
        return Command(goto="execute_action", update={"proposal": proposal, "steps": _bump(state),
                       "trace": [f"approval:approved_by:{decision.get('approver', '?')}"]})
    return Command(goto="finalize", update={"proposal": proposal, "steps": _bump(state),
                   "answer": "Action cancelled by approver. Nothing was written.",
                   "trace": ["approval:rejected"]})


def execute_action(state: QAState) -> dict:
    """Idempotent write: key = hash(thread + proposal). A retried/resumed run cannot
    create a second CAPA."""
    key = hashlib.sha256((str(state.get("thread_id")) + json.dumps(state["proposal"], sort_keys=True))
                         .encode()).hexdigest()[:16]
    if key not in ACTION_LOG:
        ACTION_LOG[key] = {"capa_id": f"CAPA-{len(ACTION_LOG) + 1:05d}", **state["proposal"]}
    rec = ACTION_LOG[key]
    return {"action_result": rec, "answer": f"Created {rec['capa_id']} (idempotency key {key}).",
            "steps": _bump(state), "trace": [f"execute_action:{rec['capa_id']}"]}


def finalize(state: QAState) -> dict:
    if state.get("answer"):            # set by approval/execute paths
        return {"trace": ["finalize:action"]}
    v = state.get("verdict") or {"ok": False}
    if not v.get("ok"):
        return {"answer": NOT_FOUND, "trace": ["finalize:not_found"]}
    by_id = {p["id"]: p for p in state["passages"]}
    lines = []
    if state.get("mode") == "search_only":
        lines.append("Model unavailable - verbatim excerpts from approved documents:")
    for s in state["draft"]:
        links = ", ".join(by_id[c]["link"] for c in s["cites"])
        body = f"\"{s['text']}\"" if s.get("verbatim") else s["text"]
        lines.append(f"{body} [{', '.join(s['cites'])}] ({links})")
    return {"answer": "\n".join(lines), "trace": ["finalize:answer"]}


# =============================================================================
# Build
# =============================================================================
def build_graph(checkpointer=None):
    g = StateGraph(QAState)
    g.add_node("supervisor", supervisor)
    g.add_node("procedure", procedure_agent)
    g.add_node("spec", spec_agent)
    g.add_node("incident", incident_agent)
    g.add_node("verifier", verifier)
    g.add_node("approval", approval)
    g.add_node("execute_action", execute_action)
    g.add_node("finalize", finalize)
    g.add_edge(START, "supervisor")
    g.add_edge("procedure", "verifier")
    g.add_edge("spec", "verifier")
    g.add_edge("incident", "verifier")
    g.add_edge("execute_action", "finalize")
    g.add_edge("finalize", END)
    # Production: durable checkpointer, e.g.
    #   from langgraph.checkpoint.postgres import PostgresSaver   # pip install langgraph-checkpoint-postgres
    #   with PostgresSaver.from_conn_string(DB_URI) as cp: cp.setup(); graph = g.compile(checkpointer=cp)
    # (Aurora PostgreSQL / Cloud SQL in an EU region, encrypted with the tenant's KMS key.)
    return g.compile(checkpointer=checkpointer or InMemorySaver())


def ask(graph, question: str, thread_id: Optional[str] = None) -> dict:
    thread_id = thread_id or uuid.uuid4().hex[:8]
    cfg = {"configurable": {"thread_id": thread_id}, "recursion_limit": 15}
    return graph.invoke({"question": question, "thread_id": thread_id, "steps": 0, "answer": ""}, cfg)


if __name__ == "__main__":
    import logging
    logging.getLogger("byom.audit").setLevel(logging.WARNING)   # keep demo output readable
    print(f"backend = {BACKEND}\n")
    graph = build_graph()
    for q in ["What is the procedure before opening the chamber lid on ETCH-2?",
              "What is the anneal temperature spec for RTP-3?",
              "What is the anneal temperature spec for RTP-9?",
              "Have we seen wafer breakage on RTP-3 before? What was the root cause?"]:
        out = ask(graph, q)
        print(f"Q: {q}\nA: {out['answer']}\ntrace: {out['trace']}\n")

    print("--- hallucinated number on first draft: verifier rejects, one retry, then passes ---")
    GATEWAY.providers["mock"].responder = make_responder(hallucinate_times=1)
    out = ask(graph, "Have we seen wafer breakage on RTP-3 before? What was the root cause?")
    print(f"A: {out['answer']}\ntrace: {out['trace']}\n")

    print("--- always hallucinates: bounded retry, then refuses ---")
    GATEWAY.providers["mock"].responder = make_responder(hallucinate_times=99)
    out = ask(graph, "Have we seen wafer breakage on RTP-3 before? What was the root cause?")
    print(f"A: {out['answer']}\ntrace: {out['trace']}\n")
    GATEWAY.providers["mock"].responder = make_responder()

    print("--- human-in-the-loop write action ---")
    cfg = {"configurable": {"thread_id": "capa-1"}, "recursion_limit": 15}
    first = graph.invoke({"question": "Open a CAPA for the particle excursion on ETCH-2",
                          "thread_id": "capa-1", "steps": 0, "answer": ""}, cfg)
    print("paused with:", first["__interrupt__"][0].value)
    done = graph.invoke(Command(resume={"approved": True, "approver": "process.eng.lead"}), cfg)
    print("A:", done["answer"], "\ntrace:", done["trace"])
