"""Permission- and classification-aware retrieval over an in-memory index.

Reference system: EU sovereign engineering-knowledge Q&A for a semiconductor
manufacturer (SOPs, spec tables, incident reports).

Design points this module demonstrates (stdlib only):
  * Authorisation is applied INSIDE the search (pre-filter), before similarity
    ranking, so unauthorised chunks never influence top-k, scores or counts.
  * Filters: user groups (ACL), classification vs clearance, revision == current,
    export-control flag vs principal's export authorisation, data region.
  * A second gate decides whether an *authorised* chunk may be placed in a
    model's context ("never send to AI" policy). A cleared engineer may be
    allowed to SEE a restricted spec in the UI, but the agent must not ship it
    to a model unless the model profile is approved for that classification.
  * The audit record contains metadata only (ids + reason codes), never text.

The embedding is a toy hashed bag-of-words; swap in the customer's BYOM
embedding model in production.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

CLASS_LEVELS = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
# Canonical "EU only" allow-list: EU MEMBER-STATE regions only. Keep identical to
# policies/rego/terraform/residency_cmk.rego, policies/cedar/eng_qa.cedar and
# policies/rego/k8s/workload_guardrails.rego. Explicitly NOT EU: eu-west-2 /
# europe-west2 (London, UK), eu-central-2 / europe-west6 (Zurich, CH), Norway.
EU_REGIONS = frozenset({
    # AWS: Frankfurt, Ireland, Paris, Milan, Spain, Stockholm
    "eu-central-1", "eu-west-1", "eu-west-3", "eu-south-1", "eu-south-2", "eu-north-1",
    # Google Cloud: Belgium, Frankfurt, Netherlands, Milan, Paris, Madrid, Finland, Warsaw
    "europe-west1", "europe-west3", "europe-west4", "europe-west8", "europe-west9",
    "europe-southwest1", "europe-north1", "europe-central2",
})


# --------------------------------------------------------------------------- #
# Toy embedding (replace with BYOM embedding endpoint inside the boundary)
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"[a-z0-9]+")


def embed(text: str, dims: int = 256) -> tuple[float, ...]:
    vec = [0.0] * dims
    for tok, n in Counter(_TOKEN.findall(text.lower())).items():
        h = int.from_bytes(hashlib.sha256(tok.encode()).digest()[:4], "big")
        vec[h % dims] += float(n)
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return tuple(v / norm for v in vec)


def cosine(a: Iterable[float], b: Iterable[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    doc_id: str
    revision: int
    text: str
    classification: str                     # public|internal|confidential|restricted
    allowed_groups: frozenset[str]
    export_controlled: bool = False
    eccn: str | None = None                 # e.g. "3E001" (EU dual-use Annex I entry)
    region: str = "eu-central-1"
    doc_type: str = "sop"                   # sop|spec_table|incident_report
    embedding: tuple[float, ...] = field(default=(), compare=False, repr=False)


@dataclass(frozen=True)
class Principal:
    user_id: str
    groups: frozenset[str]
    clearance: str = "internal"
    export_authorised_eccns: frozenset[str] = frozenset()   # ECCNs user may access
    location_country: str = "DE"


@dataclass(frozen=True)
class ModelProfile:
    """What a given model endpoint is approved to receive."""
    model_id: str
    region: str
    in_boundary: bool                       # self-hosted/BYOM inside customer boundary
    max_classification: str = "internal"
    export_control_approved: bool = False


@dataclass
class Decision:
    chunk_id: str
    allowed: bool
    reasons: list[str]


@dataclass
class SearchResult:
    hits: list[tuple[float, Chunk]]
    audit: list[Decision]                   # metadata only: ids + reason codes

    def audit_log(self) -> list[dict]:
        return [{"chunk": d.chunk_id, "allowed": d.allowed, "reasons": d.reasons}
                for d in self.audit]


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
EU_EEA = frozenset({"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
                    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
                    "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO"})


def access_reasons(chunk: Chunk, p: Principal, current_rev: int) -> list[str]:
    """Return list of deny reason codes; empty list == allowed to read."""
    reasons: list[str] = []
    if chunk.revision != current_rev:
        reasons.append("STALE_REVISION")
    if not (chunk.allowed_groups & p.groups):
        reasons.append("NO_GROUP_MATCH")
    if CLASS_LEVELS[chunk.classification] > CLASS_LEVELS[p.clearance]:
        reasons.append("CLEARANCE_TOO_LOW")
    if chunk.export_controlled:
        if chunk.eccn not in p.export_authorised_eccns:
            reasons.append("EXPORT_NOT_AUTHORISED")
        # Location check is a placeholder: real deemed-export / intangible
        # transfer rules need trade-compliance input, not code.
        if p.location_country not in EU_EEA:
            reasons.append("EXPORT_LOCATION")
    if chunk.region not in EU_REGIONS:
        reasons.append("NON_EU_REGION")
    return reasons


def model_egress_reasons(chunk: Chunk, m: ModelProfile) -> list[str]:
    """Second gate: may this (already authorised) chunk be sent to model m?"""
    reasons: list[str] = []
    if chunk.classification == "restricted":
        reasons.append("NEVER_TO_MODEL_RESTRICTED")
    elif CLASS_LEVELS[chunk.classification] > CLASS_LEVELS[m.max_classification]:
        reasons.append("MODEL_NOT_APPROVED_FOR_CLASS")
    if chunk.export_controlled and not (m.export_control_approved and m.in_boundary):
        reasons.append("EXPORT_CONTROLLED_TO_MODEL")
    if m.region not in EU_REGIONS:
        reasons.append("MODEL_NON_EU")
    return reasons


# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #
class InMemoryIndex:
    def __init__(self) -> None:
        self._chunks: dict[str, Chunk] = {}
        self._current_rev: dict[str, int] = {}

    def add(self, chunk: Chunk) -> None:
        if not chunk.embedding:
            chunk = Chunk(**{**chunk.__dict__, "embedding": embed(chunk.text)})
        self._chunks[chunk.chunk_id] = chunk
        self._current_rev[chunk.doc_id] = max(
            self._current_rev.get(chunk.doc_id, 0), chunk.revision)

    def set_current_revision(self, doc_id: str, rev: int) -> None:
        self._current_rev[doc_id] = rev

    def current_revisions(self, doc_ids: Iterable[str]) -> dict[str, int]:
        return {d: self._current_rev[d] for d in doc_ids if d in self._current_rev}

    def delete_doc(self, doc_id: str) -> int:
        ids = [c for c, ch in self._chunks.items() if ch.doc_id == doc_id]
        for c in ids:
            del self._chunks[c]
        self._current_rev.pop(doc_id, None)
        return len(ids)

    def search(self, query: str, principal: Principal, k: int = 3,
               model: ModelProfile | None = None) -> SearchResult:
        """Filter-then-rank. If `model` is given, also apply the egress gate."""
        qv = embed(query)
        audit: list[Decision] = []
        candidates: list[tuple[float, Chunk]] = []
        for ch in self._chunks.values():
            reasons = access_reasons(ch, principal, self._current_rev[ch.doc_id])
            if not reasons and model is not None:
                reasons = model_egress_reasons(ch, model)
            audit.append(Decision(ch.chunk_id, not reasons, reasons))
            if not reasons:                 # score ONLY authorised chunks
                candidates.append((cosine(qv, ch.embedding), ch))
        candidates.sort(key=lambda t: t[0], reverse=True)
        return SearchResult(candidates[:k], audit)


# --------------------------------------------------------------------------- #
# Demo corpus
# --------------------------------------------------------------------------- #
def demo_index() -> InMemoryIndex:
    idx = InMemoryIndex()
    rows = [
        Chunk("sop-12#r1", "sop-12", 1, "SOP wet etch bath change procedure rev1 HF concentration 49%",
              "internal", frozenset({"fab-ops"})),
        Chunk("sop-12#r2", "sop-12", 2, "SOP wet etch bath change procedure rev2 HF concentration 49% add PPE check",
              "internal", frozenset({"fab-ops"})),
        Chunk("spec-7", "spec-7", 1, "Spec table gate oxide thickness target 1.2 nm process window N3 etch",
              "confidential", frozenset({"process-eng"}), doc_type="spec_table"),
        Chunk("inv-3", "inv-3", 1, "Unpublished invention: novel etch chemistry for GAA nanosheet release",
              "restricted", frozenset({"process-eng"}), export_controlled=True, eccn="3E001",
              doc_type="spec_table"),
        Chunk("inc-44", "inc-44", 1, "Incident report: etch chamber arcing, root cause RF match drift",
              "internal", frozenset({"fab-ops", "process-eng"}), doc_type="incident_report"),
        Chunk("us-1", "us-1", 1, "Etch vendor manual mirrored in us-east-1 (should never be indexed)",
              "internal", frozenset({"fab-ops"}), region="us-east-1"),
    ]
    for r in rows:
        idx.add(r)
    return idx


if __name__ == "__main__":
    idx = demo_index()
    alice = Principal("alice", frozenset({"fab-ops"}), "internal")
    bob = Principal("bob", frozenset({"process-eng"}), "restricted",
                    export_authorised_eccns=frozenset({"3E001"}))
    byom = ModelProfile("byom-llm-eu", "eu-central-1", in_boundary=True,
                        max_classification="confidential")
    for who in (alice, bob):
        r = idx.search("etch procedure", who, k=5)
        print(f"[{who.user_id}] UI view  ->", [c.chunk_id for _, c in r.hits])
        r = idx.search("etch procedure", who, k=5, model=byom)
        print(f"[{who.user_id}] to model ->", [c.chunk_id for _, c in r.hits])
    print("audit sample (bob, to model):")
    for row in idx.search("etch", bob, model=byom).audit_log():
        print("  ", row)
