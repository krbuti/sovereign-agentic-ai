"""Unit tests for byom_gateway_v2 and sovereign_agents. Run: python3 -m unittest -v test_all"""
import logging
import random
import threading
import unittest

logging.getLogger("byom.audit").setLevel(logging.CRITICAL)

import byom_gateway_v2 as g
import sovereign_agents as a

logging.getLogger("byom.audit").setLevel(logging.CRITICAL)


def req(text="What is the anneal limit?", **kw):
    return g.ChatRequest(system="sys", messages=[{"role": "user", "content": text}], **kw)


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.gw, self.mock = g.build_demo_gateway()

    # --- role resolution & sovereignty ---------------------------------------
    def test_role_resolves_to_tenant_model(self):
        self.assertEqual(self.gw.chat("fab-eu", "router", req()).model_id, "claude-haiku-eu")
        self.assertEqual(self.gw.chat("fab-eu", "reasoning", req()).model_id, "claude-sonnet-eu")

    def test_region_policy_endpoint_kinds(self):
        rp = self.gw.tenants["fab-eu"].region_policy
        M = lambda **kw: g.ModelSpec(id="x", provider="mock", **{"model_ref": "m", **kw})
        with self.assertRaises(g.PolicyViolation): rp.check(M(endpoint_kind="global", region="global"))
        with self.assertRaises(g.PolicyViolation): rp.check(M(endpoint_kind="regional", region="us-east-1"))
        with self.assertRaises(g.PolicyViolation): rp.check(M(endpoint_kind="regional", region="eu-west-2"))  # London
        with self.assertRaises(g.PolicyViolation): rp.check(M(endpoint_kind="geo_profile", region="eu-west-1",
                                                                 model_ref="global.anthropic.x"))
        with self.assertRaises(g.PolicyViolation): rp.check(M(endpoint_kind="data_zone", region="swedencentral"))
        rp.check(M(endpoint_kind="geo_profile", region="eu-west-1", model_ref="eu.anthropic.x"))
        rp.check(M(endpoint_kind="multi_region", region="eu"))
        rp.eu_scope = "eu_data_boundary"
        rp.check(M(endpoint_kind="data_zone", region="swedencentral"))  # allowed only in this scope

    def test_same_region_only_policy(self):
        self.gw.tenants["fab-eu"].roles["reasoning"].fallback_policy = "same_region_only"
        self.mock.script["claude-sonnet-eu"] = ["transient"] * 3
        with self.assertRaises(g.SearchOnlyMode):   # qwen is eu-central-1, sonnet's region is eu-west-1
            self.gw.chat("fab-eu", "reasoning", req())

    # --- eval gate & capability ----------------------------------------------
    def test_unevaluated_fallback_skipped_then_activated(self):
        t = self.gw.tenants["fab-eu"]
        t.roles["reasoning"].fallbacks = ["llama-dedicated-eu"]
        self.mock.script["claude-sonnet-eu"] = ["permanent"]
        with self.assertRaises(g.SearchOnlyMode):
            self.gw.chat("fab-eu", "reasoning", req())
        score = g.run_golden_set(self.gw, "fab-eu", "llama-dedicated-eu",
                                 [{"system": "s", "question": "q1"}, {"system": "s", "question": "q2"}],
                                 scorer=lambda text, case: 1.0 if case["question"] in text else 0.0)
        self.assertTrue(self.gw.registry.activate("llama-dedicated-eu", score, "gs-2026-11-01", "2026-11-21"))
        self.mock.script["claude-sonnet-eu"] = ["permanent"]
        self.assertEqual(self.gw.chat("fab-eu", "reasoning", req()).model_id, "llama-dedicated-eu")

    def test_stale_golden_set_version_fails_gate(self):
        self.gw.registry.golden_set_version = "gs-2026-12-01"   # golden set updated -> all must re-pass
        with self.assertRaises(g.SearchOnlyMode):
            self.gw.chat("fab-eu", "router", req())

    def test_capability_check(self):
        # router fallback mistral has 32k context; force primary down and require 100k
        self.mock.script["claude-haiku-eu"] = ["permanent"]
        with self.assertRaises(g.SearchOnlyMode):
            self.gw.chat("fab-eu", "router", req(needs=g.Needs(min_context=100_000)))
        with self.assertRaises(g.SearchOnlyMode):   # haiku lacks table_understanding, mistral too
            self.gw.chat("fab-eu", "router", req(needs=g.Needs(table_understanding=True)))

    # --- retries, jitter, breaker, deadline -----------------------------------
    def test_full_jitter_bounds_and_retry(self):
        rp = g.RetryPolicy(max_attempts=5, base_s=0.1, cap_s=1.0)
        rng = random.Random(1)
        for attempt in range(8):
            d = rp.backoff(attempt, rng)
            self.assertTrue(0 <= d <= min(1.0, 0.1 * 2 ** attempt))
        sleeps = []
        self.gw.sleep = sleeps.append
        self.mock.script["claude-sonnet-eu"] = ["transient", "transient"]
        self.assertEqual(self.gw.chat("fab-eu", "reasoning", req()).model_id, "claude-sonnet-eu")
        self.assertEqual(len(sleeps), 2)
        self.assertEqual(len(set(sleeps)), 2)     # jittered, not identical

    def test_permanent_error_not_retried(self):
        sleeps = []
        self.gw.sleep = sleeps.append
        self.mock.script["claude-sonnet-eu"] = ["permanent", "ok"]
        r = self.gw.chat("fab-eu", "reasoning", req())
        self.assertEqual(r.model_id, "qwen-dedicated-eu-c1")   # moved on, no retry of same call
        self.assertEqual(sleeps, [])

    def test_circuit_breaker_open_half_open_close(self):
        clk = FakeClock()
        br = g.CircuitBreaker(failure_threshold=3, window_s=60, cooldown_s=30, clock=clk)
        for _ in range(3): br.record_failure()
        self.assertEqual(br.state, "open"); self.assertFalse(br.allow())
        clk.advance(31)
        self.assertTrue(br.allow()); self.assertEqual(br.state, "half_open")
        self.assertFalse(br.allow())               # only one probe
        br.record_success(); self.assertEqual(br.state, "closed")
        for _ in range(3): br.record_failure()
        clk.advance(31); br.allow(); br.record_failure()
        self.assertEqual(br.state, "open")         # failed probe re-opens

    def test_breaker_skips_model_without_calling(self):
        self.gw.breaker("claude-sonnet-eu").state = "open"
        self.gw.breaker("claude-sonnet-eu").opened_at = self.gw.clock()
        n_before = len(self.mock.received)
        r = self.gw.chat("fab-eu", "reasoning", req())
        self.assertEqual(r.model_id, "qwen-dedicated-eu-c1")
        self.assertEqual([m for m, _ in self.mock.received[n_before:]], ["qwen-dedicated-eu-c1"])

    def test_timeout_is_transient_and_falls_back(self):
        self.mock.latency_ms["claude-sonnet-eu"] = 60_000   # > model timeout -> ReadTimeout
        self.assertEqual(self.gw.chat("fab-eu", "reasoning", req()).model_id, "qwen-dedicated-eu-c1")

    def test_deadline_exceeded(self):
        clk = FakeClock()
        self.gw.clock = clk
        self.gw.sleep = clk.advance
        self.gw.tenants["fab-eu"].request_deadline_s = 0.15
        self.gw.retry = g.RetryPolicy(max_attempts=10, base_s=1.0, cap_s=1.0)
        self.gw.rng = random.Random(3)
        self.mock.script["claude-sonnet-eu"] = ["transient"] * 10
        self.mock.script["qwen-dedicated-eu-c1"] = ["transient"] * 10
        with self.assertRaises(g.SearchOnlyMode):
            self.gw.chat("fab-eu", "reasoning", req())

    # --- budget ----------------------------------------------------------------
    def test_budget_atomic_under_concurrency(self):
        store = g.InMemoryBudgetStore()
        ok = []
        def worker():
            ok.append(store.reserve("k", 10, 105, 60))
        ts = [threading.Thread(target=worker) for _ in range(50)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(sum(ok), 10); self.assertEqual(store.used("k"), 100)

    def test_budget_reserve_then_reconcile_and_exhaustion(self):
        gw, mock = g.build_demo_gateway(budget_tokens=2_000)
        key = gw._budget_key("fab-eu")
        r = gw.chat("fab-eu", "router", req(max_tokens=500))
        self.assertEqual(gw.budget.used(key), r.input_tokens + r.output_tokens)  # reservation reconciled
        with self.assertRaises(g.SearchOnlyMode) as cm:
            gw.chat("fab-eu", "router", req(max_tokens=5_000))
        self.assertEqual(cm.exception.reason, "token_budget_exhausted")

    def test_failed_call_releases_reservation(self):
        key = self.gw._budget_key("fab-eu")
        self.mock.script["claude-haiku-eu"] = ["permanent"]
        self.mock.script["mistral-small-dedicated"] = ["permanent"]
        with self.assertRaises(g.SearchOnlyMode):
            self.gw.chat("fab-eu", "router", req())
        self.assertEqual(self.gw.budget.used(key), 0)

    # --- masking & audit ---------------------------------------------------------
    def test_pii_masked_before_model_numbers_untouched(self):
        txt = ("Jane Murphy jane.murphy@fab.example +353 89 123 4567 EMP-004211 IBAN DE89 3704 0044 0532 0130 00 "
               "asks about 350 ± 5 °C, 0.8 mTorr, lot L2026-0412, 760 Torr")
        r = self.gw.chat("fab-eu", "reasoning", req(txt))
        seen = self.mock.received[-1][1]
        for pii in ["Jane Murphy", "jane.murphy@fab.example", "+353 89 123 4567", "EMP-004211", "DE89 3704"]:
            self.assertNotIn(pii, seen)
        for keep in ["350 ± 5 °C", "0.8 mTorr", "L2026-0412", "760 Torr"]:
            self.assertIn(keep, seen)
        self.assertIn("Jane Murphy", r.text)     # restored for the end user

    def test_audit_contains_no_raw_prompt(self):
        with self.assertLogs("byom.audit", level="INFO") as logs:
            logging.getLogger("byom.audit").setLevel(logging.INFO)
            self.gw.chat("fab-eu", "reasoning", req("secret recipe step for jane.murphy@fab.example"))
        logging.getLogger("byom.audit").setLevel(logging.CRITICAL)
        blob = "\n".join(logs.output)
        self.assertNotIn("secret recipe", blob); self.assertNotIn("jane.murphy", blob)
        self.assertIn("prompt_sha256", blob); self.assertIn('"event": "ok"', blob)

    # --- SLO / cost ------------------------------------------------------------------
    def test_latency_percentiles_and_slo_breach_demotes(self):
        lt = g.LatencyTracker(min_samples=20)
        for i in range(1, 101):
            lt.record("m", float(i), None)
        s = lt.snapshot("m")
        self.assertEqual((s["p50_ms"], s["p95_ms"], s["p99_ms"]), (50.0, 95.0, 99.0))
        for _ in range(25):
            self.gw.latency.record("claude-sonnet-eu", 9_000, None)   # SLO p95 is 6000
        self.assertEqual(self.gw.chat("fab-eu", "reasoning", req()).model_id, "qwen-dedicated-eu-c1")

    def test_cost_per_task(self):
        self.gw.chat("fab-eu", "router", req(), task_id="T1")
        self.gw.chat("fab-eu", "reasoning", req(), task_id="T1")
        self.assertEqual(self.gw.costs.tasks["T1"]["calls"], 2)
        self.assertGreater(self.gw.costs.tasks["T1"]["eur"], 0)

    # --- embeddings ------------------------------------------------------------------
    def test_embedding_never_mixes_models(self):
        self.assertEqual(len(self.gw.embed("fab-eu", ["x"])[0]), 8)
        self.gw.indexes.register("idx-v4-other", "other-embed", 1024)
        self.gw.indexes.mark_eval("idx-v4-other", True)
        self.gw.indexes.switch("fab-eu", "idx-v4-other")
        with self.assertRaises(g.PolicyViolation):
            self.gw.embed("fab-eu", ["x"])        # query model != index model -> refuse

    def test_index_switch_requires_eval(self):
        self.gw.indexes.register("idx-v5", "titan-embed-eu", 8)
        with self.assertRaises(g.PolicyViolation):
            self.gw.indexes.switch("fab-eu", "idx-v5")

    def test_embedding_outage_goes_search_only(self):
        self.mock.script["titan-embed-eu"] = ["transient"] * 3
        with self.assertRaises(g.SearchOnlyMode):
            self.gw.embed("fab-eu", ["x"])


class AgentTests(unittest.TestCase):
    def setUp(self):
        a.GATEWAY.providers["mock"].responder = a.make_responder()
        a.GATEWAY.providers["mock"].script.clear()
        a.GATEWAY.breakers.clear()
        a.GATEWAY.sleep = lambda s: None
        self.graph = a.build_graph()

    def test_procedure_is_verbatim_with_link(self):
        out = a.ask(self.graph, "What is the procedure before opening the chamber lid on ETCH-2?")
        self.assertIn(a.SOPS[0]["text"], out["answer"])
        self.assertIn(a.SOPS[0]["link"], out["answer"])

    def test_spec_exact_value(self):
        out = a.ask(self.graph, "What is the anneal temperature spec for RTP-3?")
        self.assertIn("350 ± 5 °C", out["answer"])

    def test_unknown_spec_not_found(self):
        out = a.ask(self.graph, "What is the anneal temperature spec for RTP-9?")
        self.assertEqual(out["answer"], a.NOT_FOUND)

    def test_verifier_catches_wrong_number(self):
        v = a.verify([{"text": "Ramp rate was set to 80 °C/s.", "cites": ["INC-2025-117"]}], a.INCIDENTS)
        self.assertFalse(v["ok"])
        v = a.verify([{"text": "Ramp rate was set to 75 °C/s.", "cites": ["INC-2025-117"]}], a.INCIDENTS)
        self.assertTrue(v["ok"])
        v = a.verify([{"text": "Ramp rate was 75 °C/s.", "cites": ["NOT-RETRIEVED"]}], a.INCIDENTS)
        self.assertFalse(v["ok"])

    def test_bounded_retry_then_refuse(self):
        a.GATEWAY.providers["mock"].responder = a.make_responder(hallucinate_times=99)
        out = a.ask(self.graph, "Have we seen wafer breakage on RTP-3 before? What was the root cause?")
        self.assertEqual(out["answer"], a.NOT_FOUND)
        self.assertEqual(out["verify_attempts"], a.MAX_VERIFY_ATTEMPTS)

    def test_retry_recovers(self):
        a.GATEWAY.providers["mock"].responder = a.make_responder(hallucinate_times=1)
        out = a.ask(self.graph, "Have we seen wafer breakage on RTP-3 before? What was the root cause?")
        self.assertIn("75 °C/s", out["answer"]); self.assertNotIn("80", out["answer"])

    def test_model_outage_search_only_answer(self):
        a.GATEWAY.providers["mock"].script["claude-sonnet-eu"] = ["transient"] * 3
        a.GATEWAY.providers["mock"].script["qwen-dedicated-eu-c1"] = ["transient"] * 3
        out = a.ask(self.graph, "Have we seen wafer breakage on RTP-3 before? What was the root cause?")
        self.assertIn("verbatim excerpts", out["answer"]); self.assertIn("INC-2025-117", out["answer"])

    def test_hitl_approve_is_idempotent(self):
        cfg = {"configurable": {"thread_id": "t-approve"}, "recursion_limit": 15}
        first = self.graph.invoke({"question": "Open a CAPA for the particle excursion on ETCH-2",
                                   "thread_id": "t-approve", "steps": 0, "answer": ""}, cfg)
        self.assertEqual(first["__interrupt__"][0].value["type"], "approval_required")
        n = len(a.ACTION_LOG)
        done = self.graph.invoke(a.Command(resume={"approved": True, "approver": "lead"}), cfg)
        self.assertTrue(done["answer"].startswith("Created CAPA-"))
        self.assertEqual(len(a.ACTION_LOG), n + 1)
        # replaying the same approved action (e.g. after a crash) must not create a duplicate
        a.execute_action(done)
        self.assertEqual(len(a.ACTION_LOG), n + 1)

    def test_hitl_reject_writes_nothing(self):
        cfg = {"configurable": {"thread_id": "t-reject"}, "recursion_limit": 15}
        self.graph.invoke({"question": "Create a ticket for RF arcing on ETCH-2", "thread_id": "t-reject",
                           "steps": 0, "answer": ""}, cfg)
        n = len(a.ACTION_LOG)
        done = self.graph.invoke(a.Command(resume={"approved": False}), cfg)
        self.assertIn("cancelled", done["answer"]); self.assertEqual(len(a.ACTION_LOG), n)

    def test_recursion_limit_enforced(self):
        a.GATEWAY.providers["mock"].responder = a.make_responder(hallucinate_times=99)
        cfg = {"configurable": {"thread_id": "t-rl"}, "recursion_limit": 3}
        with self.assertRaises(a.GraphRecursionError):
            self.graph.invoke({"question": "Have we seen wafer breakage on RTP-3 before?",
                               "thread_id": "t-rl", "steps": 0, "answer": ""}, cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
