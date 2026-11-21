#!/usr/bin/env python3
"""Unit tests for eval_harness.py (stdlib unittest). Run: python3 -m unittest -v test_eval_harness"""
import json
import unittest
from pathlib import Path

import eval_harness as h

HERE = Path(__file__).resolve().parent
CFG = json.loads((HERE / "thresholds.json").read_text())
ITEMS = h.load_jsonl(HERE / "golden_set.jsonl")


class NumberMatching(unittest.TestCase):
    def test_value_and_unit_must_match(self):
        nums = h.extract_numbers("Overlay tolerance is 4.5 nm at 3 sigma.")
        self.assertTrue(h.number_present("4.5 nm", nums))
        self.assertFalse(h.number_present("4.5 mm", nums))
        self.assertFalse(h.number_present("5 nm", nums))

    def test_scientific_notation(self):
        self.assertTrue(h.number_present("5e15 cm-2", h.extract_numbers("dose 5e15 cm-2 at tilt")))

    def test_rounded_paraphrase_fails(self):
        self.assertFalse(h.number_present("4.5 nm", h.extract_numbers("about 4 nm")))


class Gates(unittest.TestCase):
    def test_min_max(self):
        fails = h.check_gates({"faithfulness": 0.80, "out_of_region_calls": 1}, {
            "faithfulness": {"min": 0.85}, "out_of_region_calls": {"max": 0}})
        self.assertEqual(len(fails), 2)

    def test_missing_metric_fails_closed(self):
        self.assertTrue(h.check_gates({}, {"faithfulness": {"min": 0.85}}))


class EndToEnd(unittest.TestCase):
    def run_sys(self, model="eu-large-a", faults=()):
        return h.run(model, set(faults), ITEMS, CFG, HERE / "corpus.json")["metrics"]

    def test_baseline_passes(self):
        self.assertEqual(h.check_gates(self.run_sys(), CFG["gates"]), [])

    def test_each_fault_trips_its_gate(self):
        expect = {"region": "out_of_region_calls", "acl": "permission_violations",
                  "stale": "superseded_revision_answers", "mixed-index": "index_consistency_violations",
                  "audit": "audit_completeness"}
        for fault, gate in expect.items():
            with self.subTest(fault=fault):
                fails = h.check_gates(self.run_sys(faults=[fault]), CFG["gates"])
                self.assertTrue(any(f.startswith(gate) for f in fails), fails)

    def test_indirect_prompt_injection_detected_when_sanitizer_off(self):
        saved = h.INJECTION_PATTERNS
        try:
            h.INJECTION_PATTERNS = []
            m = self.run_sys()
            self.assertGreaterEqual(m["injection_followed"], 1)
        finally:
            h.INJECTION_PATTERNS = saved

    def test_model_swap_blocked(self):
        base, cand = self.run_sys("eu-large-a"), self.run_sys("eu-large-b")
        self.assertTrue(h.compare_swap(base, cand, CFG["model_swap"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
