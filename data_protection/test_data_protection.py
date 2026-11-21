"""Unit tests for the data-protection reference code. Run: python3 test_data_protection.py -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dlp import Action, default_engine  # noqa: E402
from key_rotation import KeyError_, KeyRing, Platform  # noqa: E402
from retrieval_filter import EU_REGIONS, ModelProfile, Principal, demo_index  # noqa: E402
from semantic_cache import SemanticCache, exact_cache_key  # noqa: E402

ALICE = Principal("alice", frozenset({"fab-ops"}), "internal")
BOB = Principal("bob", frozenset({"process-eng"}), "restricted",
                export_authorised_eccns=frozenset({"3E001"}))
BOB_NO_EXPORT = Principal("bob2", frozenset({"process-eng"}), "restricted")
BOB_OUTSIDE_EU = Principal("bob3", frozenset({"process-eng"}), "restricted",
                           export_authorised_eccns=frozenset({"3E001"}), location_country="US")
BYOM = ModelProfile("byom", "eu-central-1", in_boundary=True, max_classification="confidential",
                    export_control_approved=True)
SAAS_US = ModelProfile("saas", "us-east-1", in_boundary=False, max_classification="internal")


def ids(res):
    return {c.chunk_id for _, c in res.hits}


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.idx = demo_index()

    def test_group_acl_and_current_revision(self):
        got = ids(self.idx.search("etch bath", ALICE, k=10))
        self.assertIn("sop-12#r2", got)
        self.assertNotIn("sop-12#r1", got)          # stale revision
        self.assertNotIn("spec-7", got)             # no group / clearance
        self.assertNotIn("us-1", got)               # non-EU region

    def test_export_control(self):
        self.assertIn("inv-3", ids(self.idx.search("etch", BOB, k=10)))
        self.assertNotIn("inv-3", ids(self.idx.search("etch", BOB_NO_EXPORT, k=10)))
        self.assertNotIn("inv-3", ids(self.idx.search("etch", BOB_OUTSIDE_EU, k=10)))

    def test_restricted_never_to_model_even_if_authorised(self):
        self.assertNotIn("inv-3", ids(self.idx.search("etch", BOB, k=10, model=BYOM)))
        self.assertIn("spec-7", ids(self.idx.search("etch", BOB, k=10, model=BYOM)))

    def test_non_eu_or_lower_tier_model(self):
        self.assertEqual(ids(self.idx.search("etch", BOB, k=10, model=SAAS_US)), set())

    def test_london_and_zurich_are_not_eu(self):
        for region in ("eu-west-2", "eu-central-2", "europe-west2", "europe-west6"):
            m = ModelProfile("byom-x", region, in_boundary=True, max_classification="confidential",
                             export_control_approved=True)
            self.assertEqual(ids(self.idx.search("etch", BOB, k=10, model=m)), set(), region)
            self.assertNotIn(region, EU_REGIONS)

    def test_prefilter_unauthorised_not_scored(self):
        r = self.idx.search("novel etch chemistry nanosheet", ALICE, k=1)
        self.assertNotEqual(r.hits[0][1].chunk_id, "inv-3")

    def test_audit_has_no_text(self):
        r = self.idx.search("etch", ALICE)
        self.assertTrue(all(set(a) == {"chunk", "allowed", "reasons"} for a in r.audit_log()))

    def test_revision_bump_hides_old(self):
        self.idx.set_current_revision("inc-44", 2)
        self.assertNotIn("inc-44", ids(self.idx.search("arcing", ALICE, k=10)))


class DLPTests(unittest.TestCase):
    SECRET = ("novel etch chemistry for gaa nanosheet release uses a buffered fluoride "
              "mixture at 23 c with 40 s dwell and selective sige removal")

    def setUp(self):
        self.eng = default_engine([self.SECRET])

    def test_pii_redacted_and_reversible(self):
        r = self.eng.inspect_input("mail jan@fab.example now", session_id="s")
        self.assertEqual(r.action, Action.REDACT)
        self.assertNotIn("jan@fab.example", r.text)
        out = self.eng.inspect_output(r.text, session_id="s", authorised_to_reidentify=True)
        self.assertIn("jan@fab.example", out.text)

    def test_tokens_not_reversible_across_sessions(self):
        r = self.eng.inspect_input("mail jan@fab.example", session_id="s1")
        out = self.eng.inspect_output(r.text, session_id="s2", authorised_to_reidentify=True)
        self.assertNotIn("jan@fab.example", out.text)

    def test_credentials_block(self):
        for t in ("key AKIAABCDEFGHIJKLMNOP", "password = hunter2hunter2",
                  "-----BEGIN RSA PRIVATE KEY-----"):
            self.assertEqual(self.eng.inspect_input(t).action, Action.BLOCK, t)

    def test_label_metadata_blocks_clean_text(self):
        r = self.eng.inspect_input("innocuous looking text", labels={"restricted"})
        self.assertEqual(r.action, Action.BLOCK)
        self.assertIsNone(r.text)

    def test_text_marker_eccn_and_codename(self):
        for t in ("[CLASSIFICATION: RESTRICTED] gate stack", "relates to 3E001 technology",
                  "Project Orchid tapeout"):
            self.assertEqual(self.eng.inspect_input(t).action, Action.BLOCK, t)

    def test_pattern_dlp_misses_ip_without_labels(self):
        # The core lesson: unlabelled confidential IP passes regex DLP on input.
        r = self.eng.inspect_input("our new gate oxide target is 1.2 nm at 650 C anneal")
        self.assertEqual(r.action, Action.ALLOW)

    def test_output_fingerprint_catches_verbatim_leak(self):
        r = self.eng.inspect_output("Here you go: " + self.SECRET.upper())
        self.assertEqual(r.action, Action.BLOCK)

    def test_audit_never_contains_values(self):
        r = self.eng.inspect_input("jan@fab.example")
        self.assertNotIn("jan@fab.example", str(r.audit))

    def test_purge_session(self):
        self.eng.inspect_input("jan@fab.example", session_id="p")
        self.assertEqual(self.eng.vault.purge_session("p"), 1)


class CacheTests(unittest.TestCase):
    KW = dict(tenant="t", region="eu-central-1", model_id="m@1", policy_version="p1",
              guardrail_version="g1")

    def setUp(self):
        self.revs = {"sop-12": 2}
        self.c = SemanticCache(lambda ds: {d: self.revs[d] for d in ds if d in self.revs},
                               secret=b"k" * 32)

    def test_group_order_irrelevant(self):
        a = Principal("a", frozenset({"x", "y"}))
        b = Principal("b", frozenset({"y", "x"}))
        self.assertEqual(self.c.partition(a, **self.KW), self.c.partition(b, **self.KW))

    def test_scope_policy_model_change_new_partition(self):
        base = self.c.partition(ALICE, **self.KW)
        self.assertNotEqual(base, self.c.partition(BOB, **self.KW))
        self.assertNotEqual(base, self.c.partition(ALICE, **{**self.KW, "policy_version": "p2"}))
        self.assertNotEqual(base, self.c.partition(ALICE, **{**self.KW, "model_id": "m@2"}))

    def test_revision_and_shred_eviction(self):
        p = self.c.partition(ALICE, **self.KW)
        self.c.put(p, "change wet etch bath", "ans", {"sop-12": 2})
        self.assertEqual(self.c.get(p, "Change wet etch bath?"), "ans")
        self.revs["sop-12"] = 3
        self.assertIsNone(self.c.get(p, "change wet etch bath"))
        self.c.put(p, "change wet etch bath", "ans3", {"sop-12": 3})
        self.assertEqual(self.c.evict_doc("sop-12"), 1)

    def test_exact_key_includes_revisions(self):
        k1 = exact_cache_key(b"s" * 32, "p", "Q?", {"d": 1})
        k2 = exact_cache_key(b"s" * 32, "p", "q", {"d": 2})
        self.assertNotEqual(k1, k2)
        self.assertEqual(k1, exact_cache_key(b"s" * 32, "p", "q", {"d": 1}))


class KeyRotationTests(unittest.TestCase):
    def _platform(self):
        kek = KeyRing("k", max_versions=3, min_rotation_h=24)
        p = Platform(kek)
        for d in ("a", "b"):
            p.write(f"{d}/src", "s3", d, b"x", "eu-central-1")
            p.write(f"{d}/emb", "vec", d, b"y", "eu-central-1")
        p.write("a/idx", "search", "a", b"z", "eu-central-1", under_doc_dek=False)
        return kek, p

    def test_rotation_no_auto_reencrypt_and_destroy_blocked(self):
        kek, p = self._platform()
        kek.clock_h = 30
        kek.rotate()
        self.assertEqual(p.coverage()["pct_active"], 0.0)
        self.assertEqual(p.read("a/emb"), b"y")          # archived key still decrypts
        with self.assertRaises(KeyError_):
            p.destroy_version(1)
        p.sync()
        self.assertEqual(p.coverage()["pct_active"], 100.0)
        p.destroy_version(1)
        self.assertEqual(p.read("a/idx"), b"z")

    def test_rotation_frequency_and_cap(self):
        kek, _ = self._platform()
        with self.assertRaises(KeyError_):
            kek.rotate()                                  # < 24h
        kek.clock_h = 30; kek.rotate()
        kek.clock_h = 60; kek.rotate()
        kek.clock_h = 90
        with self.assertRaises(KeyError_):
            kek.rotate()                                  # 3 undestroyed versions

    def test_residency_enforced(self):
        _, p = self._platform()
        with self.assertRaises(ValueError):
            p.write("c/src", "s3", "c", b"x", "us-east-1")

    def test_crypto_shred(self):
        _, p = self._platform()
        rep = p.crypto_shred("a")
        self.assertEqual(rep["physically_deleted"], ["a/idx"])
        self.assertEqual(set(rep["shredded_via_dek"]), {"a/src", "a/emb"})
        with self.assertRaises(KeyError_):
            p.read("a/src")
        self.assertEqual(p.read("b/src"), b"x")


if __name__ == "__main__":
    unittest.main()
