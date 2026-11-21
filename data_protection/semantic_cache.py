"""Permission-scoped semantic cache key builder + cache.

Rule: a cached answer may only be served to a caller whose *effective access
scope* is identical to the one that produced it, generated under the same
model + policy version, and only while every source document is still at the
revision the answer was built from. Otherwise a cache becomes a side channel
that bypasses permission-aware retrieval (user B gets user A's answer that
quoted a document B cannot read) or serves superseded SOP revisions.

Two-level design:
  1. scope partition key  = HMAC(tenant, region, groups, clearance, export auths,
                                 model_id, policy_version, guardrail_version)
     -> semantic (fuzzy) lookup happens ONLY within one partition.
  2. entry validation     = stored {doc_id: revision} must equal current revisions
     -> any revision bump or deletion => miss + evict.
Keys are HMACed with an in-boundary secret so the cache store (e.g. ElastiCache /
Memorystore under CMEK) never holds group names or query text in key form.
Entries record their source doc_ids so crypto-shredding a document evicts every
answer derived from it (evict_doc).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass

from retrieval_filter import Principal, cosine, embed


def normalise_query(q: str) -> str:
    return " ".join(re.findall(r"[a-z0-9.%]+", q.lower()))


def scope_partition_key(secret: bytes, p: Principal, *, tenant: str, region: str,
                        model_id: str, policy_version: str,
                        guardrail_version: str) -> str:
    canonical = json.dumps({
        "tenant": tenant, "region": region,
        "groups": sorted(p.groups), "clearance": p.clearance,
        "export": sorted(p.export_authorised_eccns),
        "model": model_id, "policy": policy_version, "guardrail": guardrail_version,
    }, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()


def exact_cache_key(secret: bytes, partition: str, query: str,
                    source_revisions: dict[str, int]) -> str:
    """Fully-qualified key for exact-match caches (no fuzzy lookup)."""
    canonical = json.dumps({"p": partition, "q": normalise_query(query),
                            "src": sorted(source_revisions.items())},
                           separators=(",", ":"))
    return hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()


@dataclass
class Entry:
    qvec: tuple[float, ...]
    answer: str
    sources: dict[str, int]           # doc_id -> revision used
    created: float


class SemanticCache:
    def __init__(self, revision_lookup, threshold: float = 0.92, ttl_s: int = 3600,
                 secret: bytes | None = None):
        self.secret = secret or secrets.token_bytes(32)
        self.revision_lookup = revision_lookup          # callable(doc_ids)->{doc:rev}
        self.threshold, self.ttl = threshold, ttl_s
        self._parts: dict[str, list[Entry]] = {}

    def partition(self, p: Principal, **kw) -> str:
        return scope_partition_key(self.secret, p, **kw)

    def get(self, partition: str, query: str) -> str | None:
        qv = embed(normalise_query(query))
        entries = self._parts.get(partition, [])
        best, best_i = None, -1
        for i, e in enumerate(entries):
            s = cosine(qv, e.qvec)
            if s >= self.threshold and (best is None or s > best[0]):
                best, best_i = (s, e), i
        if best is None:
            return None
        e = best[1]
        if time.time() - e.created > self.ttl or self.revision_lookup(e.sources.keys()) != e.sources:
            entries.pop(best_i)                          # stale -> evict
            return None
        return e.answer

    def put(self, partition: str, query: str, answer: str, sources: dict[str, int]) -> None:
        lst = self._parts.setdefault(partition, [])
        lst.append(Entry(embed(normalise_query(query)), answer, dict(sources), time.time()))

    def evict_doc(self, doc_id: str) -> int:
        """Called by the crypto-shred / deletion workflow."""
        n = 0
        for part, entries in self._parts.items():
            keep = [e for e in entries if doc_id not in e.sources]
            n += len(entries) - len(keep)
            self._parts[part] = keep
        return n


if __name__ == "__main__":
    revs = {"sop-12": 2, "inc-44": 1}
    cache = SemanticCache(lambda ids: {i: revs[i] for i in ids if i in revs})
    kw = dict(tenant="semico", region="eu-central-1", model_id="byom-llm-eu@3",
              policy_version="pol-2026-11-01", guardrail_version="gr-7")
    a = Principal("alice", frozenset({"fab-ops"}))
    a2 = Principal("anna", frozenset({"fab-ops"}))
    b = Principal("bob", frozenset({"fab-ops", "process-eng"}), "restricted")
    pa, pa2, pb = cache.partition(a, **kw), cache.partition(a2, **kw), cache.partition(b, **kw)
    print("same scope, different user -> same partition:", pa == pa2)
    print("different scope            -> different partition:", pa != pb)
    cache.put(pa, "How do I change the wet etch bath?", "Follow SOP-12 rev2 ...", {"sop-12": 2})
    print("hit (paraphrase, same scope):", cache.get(pa2, "how do i change the wet etch bath"))
    print("miss (other scope)          :", cache.get(pb, "How do I change the wet etch bath?"))
    revs["sop-12"] = 3
    print("miss after revision bump    :", cache.get(pa, "How do I change the wet etch bath?"))
