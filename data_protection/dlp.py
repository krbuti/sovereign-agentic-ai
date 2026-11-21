"""Input/output DLP with pluggable detectors and reversible tokenisation.

Runs at the "handover point": inside the trusted boundary, AFTER decryption
(the KMS/EKM has already released plaintext to the app tier) and BEFORE text
reaches a model, a tool, a log or a cache. Output DLP runs on model responses
before they reach the user or a downstream agent.

Detectors (pluggable, all implement `detect(text, ctx) -> list[Finding]`):
  * RegexDetector         - PII + credentials (pattern-based, what Bedrock
                            Guardrails / Google SDP / Macie also do well).
  * LabelDetector         - classification labels in text markers or in chunk
                            metadata; this is how confidential IP is caught,
                            because no regex recognises an unpublished invention.
  * FingerprintDetector   - hashed 8-word shingles of restricted documents
                            (exact-data-match style) to catch verbatim leakage of
                            restricted text in model OUTPUT.

Redaction uses reversible tokens: <<EMAIL_1a2b3c4d>>. The token->value map
lives in a TokenVault inside the boundary (in production: an encrypted store
under a customer-managed key, scoped to the session, TTL'd). The model and the
logs only ever see tokens. Audit events contain kinds/offsets/actions only.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Protocol


class Action(IntEnum):          # ordered by severity; max() picks the strictest
    ALLOW = 0
    REDACT = 1
    BLOCK = 2


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    action: Action
    detector: str


@dataclass
class Context:
    direction: str = "input"                  # input|output
    labels: frozenset[str] = frozenset()      # classification labels of attached chunks
    session_id: str = "s-0"


class Detector(Protocol):
    name: str

    def detect(self, text: str, ctx: Context) -> list[Finding]: ...


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #
class RegexDetector:
    name = "regex"
    # (kind, pattern, action). Keep patterns lookaround-free so they can be
    # ported to Bedrock Guardrails regexesConfig (lookarounds unsupported there).
    DEFAULT = [
        ("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", Action.REDACT),
        ("IBAN", r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b", Action.REDACT),
        ("PHONE_EU", r"\+(?:3[0-9]|4[0-9])[ 0-9]{8,14}[0-9]", Action.REDACT),
        ("IPV4", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", Action.REDACT),
        ("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Action.BLOCK),
        ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", Action.BLOCK),
        ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", Action.BLOCK),
        ("SECRET_ASSIGNMENT", r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*\S{6,}", Action.BLOCK),
    ]

    def __init__(self, patterns=None):
        self.patterns = [(k, re.compile(p), a) for k, p, a in (patterns or self.DEFAULT)]

    def detect(self, text: str, ctx: Context) -> list[Finding]:
        return [Finding(k, m.start(), m.end(), a, self.name)
                for k, rx, a in self.patterns for m in rx.finditer(text)]


class LabelDetector:
    """Classification-label blocker (metadata first, text markers second)."""
    name = "label"

    def __init__(self, blocked_labels=frozenset({"restricted", "export-controlled"}),
                 codenames=frozenset()):
        self.blocked = blocked_labels
        self.marker = re.compile(r"\[(?:CLASSIFICATION|LABEL):\s*([A-Za-z-]+)\]", re.I)
        # EU dual-use Annex I style entry, e.g. 3E001, 3B001 (category 3 = electronics)
        self.eccn = re.compile(r"\b[0-9][A-E][0-9]{3}\b")
        self.codenames = [re.compile(rf"\b{re.escape(c)}\b", re.I) for c in codenames]

    def detect(self, text: str, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        hit = ctx.labels & self.blocked
        if hit:  # metadata says so: block the whole payload, regardless of text
            out.append(Finding("LABEL_META:" + ",".join(sorted(hit)), 0, len(text),
                               Action.BLOCK, self.name))
        for m in self.marker.finditer(text):
            if m.group(1).lower() in self.blocked:
                out.append(Finding("LABEL_MARKER:" + m.group(1).lower(), 0, len(text),
                                   Action.BLOCK, self.name))
        for m in self.eccn.finditer(text):
            out.append(Finding("ECCN_REFERENCE", m.start(), m.end(), Action.BLOCK, self.name))
        for rx in self.codenames:
            for m in rx.finditer(text):
                out.append(Finding("PROJECT_CODENAME", m.start(), m.end(), Action.BLOCK, self.name))
        return out


class FingerprintDetector:
    """Hashed word-shingle fingerprints of restricted docs (output leakage)."""
    name = "fingerprint"

    def __init__(self, key: bytes, n: int = 8):
        self.key, self.n, self.prints = key, n, set()

    def _shingles(self, text: str):
        words = re.findall(r"[a-z0-9.%]+", text.lower())
        for i in range(max(0, len(words) - self.n + 1)):
            yield hmac.new(self.key, " ".join(words[i:i + self.n]).encode(),
                           hashlib.sha256).digest()[:16]

    def register(self, restricted_text: str) -> None:
        self.prints.update(self._shingles(restricted_text))   # store hashes only

    def detect(self, text: str, ctx: Context) -> list[Finding]:
        hits = sum(1 for s in self._shingles(text) if s in self.prints)
        return [Finding(f"RESTRICTED_VERBATIM({hits})", 0, len(text), Action.BLOCK,
                        self.name)] if hits else []


# --------------------------------------------------------------------------- #
# Reversible tokenisation (kept inside the boundary)
# --------------------------------------------------------------------------- #
class TokenVault:
    TOKEN_RX = re.compile(r"<<([A-Z0-9_]+)_([0-9a-f]{8})>>")

    def __init__(self, key: bytes | None = None):
        self._key = key or secrets.token_bytes(32)          # per-deployment, from KMS in prod
        self._store: dict[tuple[str, str], str] = {}         # (session, token) -> value

    def tokenize(self, session: str, kind: str, value: str) -> str:
        digest = hmac.new(self._key, f"{session}|{kind}|{value}".encode(),
                          hashlib.sha256).hexdigest()[:8]
        tok = f"<<{kind}_{digest}>>"
        self._store[(session, tok)] = value
        return tok

    def detokenize(self, session: str, text: str) -> str:
        return self.TOKEN_RX.sub(lambda m: self._store.get((session, m.group(0)), "[REDACTED]"), text)

    def purge_session(self, session: str) -> int:
        keys = [k for k in self._store if k[0] == session]
        for k in keys:
            del self._store[k]
        return len(keys)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
@dataclass
class DLPResult:
    action: Action
    text: str | None                 # None when blocked
    findings: list[Finding]
    audit: list[dict] = field(default_factory=list)


class DLPEngine:
    def __init__(self, detectors: list[Detector], vault: TokenVault):
        self.detectors, self.vault = detectors, vault

    def _run(self, text: str, ctx: Context) -> DLPResult:
        findings = [f for d in self.detectors for f in d.detect(text, ctx)]
        action = max((f.action for f in findings), default=Action.ALLOW)
        audit = [{"dir": ctx.direction, "kind": f.kind, "span": [f.start, f.end],
                  "action": f.action.name, "detector": f.detector} for f in findings]
        if action == Action.BLOCK:
            return DLPResult(action, None, findings, audit)
        # redact right-to-left, skipping overlaps
        out, last = text, len(text) + 1
        for f in sorted((f for f in findings if f.action == Action.REDACT),
                        key=lambda f: f.start, reverse=True):
            if f.end > last:
                continue
            tok = self.vault.tokenize(ctx.session_id, f.kind, text[f.start:f.end])
            out = out[:f.start] + tok + out[f.end:]
            last = f.start
        return DLPResult(action, out, findings, audit)

    def inspect_input(self, text: str, labels=frozenset(), session_id="s-0") -> DLPResult:
        return self._run(text, Context("input", frozenset(labels), session_id))

    def inspect_output(self, text: str, session_id="s-0",
                       authorised_to_reidentify: bool = False) -> DLPResult:
        res = self._run(text, Context("output", frozenset(), session_id))
        if res.action != Action.BLOCK and authorised_to_reidentify:
            res.text = self.vault.detokenize(session_id, res.text)
        return res


def default_engine(restricted_docs=(), codenames=frozenset({"ORCHID"})) -> DLPEngine:
    fp = FingerprintDetector(secrets.token_bytes(32))
    for d in restricted_docs:
        fp.register(d)
    return DLPEngine([RegexDetector(), LabelDetector(codenames=codenames), fp], TokenVault())


if __name__ == "__main__":
    secret_spec = ("novel etch chemistry for gaa nanosheet release uses a buffered "
                   "fluoride mixture at 23 c with 40 s dwell and selective sige removal")
    eng = default_engine([secret_spec])
    q = "Ask jan.kowalski@fab.example (+49 170 1234567) why chamber 10.2.3.4 arcs"
    r = eng.inspect_input(q, session_id="s1")
    print("INPUT  :", r.action.name, "|", r.text)
    print("AUDIT  :", r.audit)
    r2 = eng.inspect_input("summarise this", labels={"restricted"}, session_id="s1")
    print("LABEL  :", r2.action.name, r2.audit)
    r3 = eng.inspect_input("debug: aws key AKIAABCDEFGHIJKLMNOP failing", session_id="s1")
    print("CRED   :", r3.action.name, [a["kind"] for a in r3.audit])
    model_out = r.text.replace("Ask", "I have notified")
    r4 = eng.inspect_output(model_out, session_id="s1", authorised_to_reidentify=True)
    print("OUTPUT :", r4.action.name, "|", r4.text)
    leak = "Sure! The process: " + secret_spec
    r5 = eng.inspect_output(leak, session_id="s1")
    print("LEAK   :", r5.action.name, [a["kind"] for a in r5.audit])
