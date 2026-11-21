"""Agent-level golden tasks with injected failures (deterministic harness).

A real evaluation drives the LLM orchestrator; here a scripted planner stands in so the
harness itself is testable offline. What is asserted is the *contract* the agent must
honour: exact value + citation when the tool succeeds, an explicit "cannot answer"
(never a fabricated number) when the tool fails, is quarantined, or is rate limited.
"""

import pytest

import server as srv
from conftest import rpc
from datastore import ReadOnlyRepository
from gateway import Gateway, Principal, ServerPolicy, ToolPolicy
from mcp import Client

GOLDEN = [
    # question, (part, parameter), expected value, unit, citation
    ("What is the max bow for WFR-3001?", ("WFR-3001", "max_bow"), "40", "um", "SPEC-WFR-3001 p.4 rev C"),
    ("Thickness tolerance of WFR-3001?", ("WFR-3001", "thickness_tolerance"), "0.0050", "mm", "SPEC-WFR-3001 p.3 rev C"),
    ("Max bake temperature of CHM-0420?", ("CHM-0420", "max_bake_temp"), "180.5", "degC", "SPEC-CHM-0420 p.12 rev F"),
]
P = Principal(sub="u", client_id="c", scopes={"spec:read"})


class FlakyRepo(ReadOnlyRepository):
    def get_spec(self, part_id, parameter):
        raise TimeoutError("upstream PLM timeout")


async def answer(question, args, db, *, repo=None, gw=None):
    """Scripted 'agent': plan -> gateway authorize -> call -> compose answer."""
    body, h = rpc("tools/call", {"name": "get_spec_value", "arguments": {"part_id": args[0], "parameter": args[1]}})
    if gw is not None:
        d = gw.authorize(P, "eng", h, body)
        if not d.allow:
            return {"answer": None, "status": f"blocked:{d.status}"}
    async with Client(srv.build_server(db, with_auth=False, repo=repo)) as c:
        r = await c.call_tool("get_spec_value", body["params"]["arguments"])
    if r.is_error:
        return {"answer": None, "status": "tool_error"}
    sc = r.structured_content
    return {"answer": f"{sc['value']} {sc['unit']}",
            "citation": f"{sc['source_doc']} p.{sc['page']} rev {sc['revision']}", "status": "ok"}


@pytest.fixture()
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("q,args,value,unit,cite", GOLDEN)
async def test_golden_exact_value_and_citation(db, q, args, value, unit, cite):
    out = await answer(q, args, db)
    assert out == {"answer": f"{value} {unit}", "citation": cite, "status": "ok"}


@pytest.mark.anyio
async def test_injected_backend_failure_no_fabrication(db):
    out = await answer(*GOLDEN[0][:2], db, repo=FlakyRepo(db))
    assert out["answer"] is None and out["status"] == "tool_error"


@pytest.mark.anyio
async def test_injected_quarantine_and_rate_limit(db):
    gw = Gateway({"eng": ServerPolicy(url="https://e", region="eu-central-1", audience="https://e",
                                      tools={"get_spec_value": ToolPolicy(scopes={"spec:read"}, rate=(1, 0.0))})})
    async with Client(srv.build_server(db, with_auth=False)) as c:
        tools = [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in (await c.list_tools()).tools]
    gw.approve("eng", tools)
    assert (await answer(*GOLDEN[0][:2], db, gw=gw))["status"] == "ok"
    assert (await answer(*GOLDEN[0][:2], db, gw=gw))["status"] == "blocked:429"
    gw.quarantined[("eng", "get_spec_value")] = "changed"
    assert (await answer(*GOLDEN[0][:2], db, gw=gw))["status"] == "blocked:403"
