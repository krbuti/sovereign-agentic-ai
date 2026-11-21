"""Unit + contract + HTTP-auth tests for the secured MCP server."""

import json
import os
import sqlite3
from decimal import Decimal
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import auth
import server as srv
from conftest import HOST, rpc
from datastore import ReadOnlyRepository
from mcp import Client

SNAPSHOT = Path(__file__).with_name("snapshots") / "tools_list.json"
CALL = ("tools/call", {"name": "get_spec_value", "arguments": {"part_id": "WFR-3001", "parameter": "thickness_tolerance"}})


@pytest.fixture()
def http(db):
    app, _ = srv.build_http_app(db)
    with TestClient(app, base_url=HOST) as c:
        yield c


def bearer(**kw):
    return {"Authorization": "Bearer " + auth.mint_demo_token(**kw)}


# ------------------------------------------------------------------ authorization (HTTP)
def test_no_token_401_with_resource_metadata(http):
    body, h = rpc(*CALL)
    r = http.post("/mcp", json=body, headers=h)
    assert r.status_code == 401
    assert 'resource_metadata="https://eng-knowledge.mcp.eu-central-1.example.internal/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]


def test_wrong_audience_401(http):
    body, h = rpc(*CALL)
    r = http.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"], audience="https://other-mcp.example.eu/mcp")})
    assert r.status_code == 401  # token minted for another resource (RFC 8707) is rejected


def test_wrong_issuer_and_expired_401(http):
    body, h = rpc(*CALL)
    assert http.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"], issuer="https://evil.example")}).status_code == 401
    assert http.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"], ttl=-120)}).status_code == 401


def test_bad_signature_401(http):
    body, h = rpc(*CALL)
    assert http.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"], secret="x" * 40)}).status_code == 401


def test_missing_scope_403_with_scope_challenge(http):
    body, h = rpc(*CALL)
    r = http.post("/mcp", json=body, headers={**h, **bearer(scopes=["incidents:read"])})
    assert r.status_code == 403
    www = r.headers["www-authenticate"]
    assert 'error="insufficient_scope"' in www and 'scope="spec:read"' in www and "resource_metadata=" in www


def test_scope_hierarchy_broad_scope_allows(http):
    body, h = rpc(*CALL)
    assert http.post("/mcp", json=body, headers={**h, **bearer(scopes=["eng:read"])}).status_code == 200


def test_token_in_query_string_not_accepted(http):
    body, h = rpc(*CALL)
    tok = auth.mint_demo_token(scopes=["spec:read"])
    assert http.post(f"/mcp?access_token={tok}", json=body, headers=h).status_code == 401


def test_prm_document(http):
    r = http.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    doc = r.json()
    assert doc["resource"] == auth.RESOURCE_URI
    assert doc["authorization_servers"] == [auth.ISSUER]
    assert set(doc["scopes_supported"]) == {"spec:read", "procedures:read", "incidents:read"}


# ------------------------------------------------------------------ transport (2026-07-28)
def test_exact_numeric_match_over_http(http):
    body, h = rpc(*CALL)
    r = http.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"])})
    assert r.status_code == 200
    res = r.json()["result"]
    sc = res["structuredContent"]
    assert res["isError"] is False
    assert sc["value"] == "0.0050"                       # exact string from controlled doc, trailing zero kept
    assert Decimal(sc["value"]) == Decimal("0.005")
    assert (sc["unit"], sc["source_doc"], sc["page"], sc["revision"]) == ("mm", "SPEC-WFR-3001", 3, "C")


def test_header_body_mismatch_400(http):
    body, h = rpc(*CALL, name_header="search_incidents")
    r = http.post("/mcp", json=body, headers={**h, **bearer(scopes=["eng:read"])})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020


def test_missing_mcp_name_header_400(http):
    body, h = rpc(*CALL, name_header=None)
    r = http.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"])})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020


def test_server_discover_and_get_405(http):
    body, h = rpc("server/discover")
    r = http.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"])})
    assert r.status_code == 200 and "2026-07-28" in r.json()["result"]["supportedVersions"]
    assert http.get("/mcp", headers=bearer(scopes=["spec:read"])).status_code == 405


def test_legacy_initialize_rejected(http):
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "old", "version": "0"}}}
    r = http.post("/mcp", json=body, headers={"Accept": "application/json, text/event-stream",
                                              "MCP-Protocol-Version": "2025-11-25", **bearer(scopes=["spec:read"])})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32022


def test_bad_host_header_rejected(db):
    app, _ = srv.build_http_app(db)
    with TestClient(app, base_url="https://attacker.example") as c:
        body, h = rpc(*CALL)
        assert c.post("/mcp", json=body, headers={**h, **bearer(scopes=["spec:read"])}).status_code in (403, 421)


# ------------------------------------------------------------------ tool behaviour (in-memory client)
@pytest.mark.anyio
async def test_tool_error_is_model_visible(db):
    async with Client(srv.build_server(db, with_auth=False)) as c:
        r = await c.call_tool("get_spec_value", {"part_id": "WFR-3001", "parameter": "warp"})
    assert r.is_error is True
    text = r.content[0].text
    assert "Available: max_bow, thickness, thickness_tolerance" in text and "Traceback" not in text


@pytest.mark.anyio
async def test_unknown_part_and_invalid_args(db):
    async with Client(srv.build_server(db, with_auth=False)) as c:
        r1 = await c.call_tool("get_spec_value", {"part_id": "ZZZ-9999", "parameter": "max_bow"})
        r2 = await c.call_tool("get_spec_value", {"part_id": "'; DROP TABLE specs;--", "parameter": "x"})
    assert r1.is_error and "Unknown part_id" in r1.content[0].text
    assert r2.is_error  # rejected by inputSchema pattern before reaching the DB


class ExplodingRepo(ReadOnlyRepository):
    def get_spec(self, part_id, parameter):
        raise RuntimeError("connect failed: postgres://svc_ro:S3cr3tPassw0rd@10.0.0.5/specs")


@pytest.mark.anyio
async def test_crash_is_masked_no_secret_leak(db):
    async with Client(srv.build_server(db, with_auth=False, repo=ExplodingRepo(db))) as c:
        r = await c.call_tool("get_spec_value", {"part_id": "WFR-3001", "parameter": "max_bow"})
    assert r.is_error is True
    assert r.content[0].text == "Error executing tool get_spec_value"
    assert "S3cr3t" not in json.dumps(r.model_dump(mode="json"))


@pytest.mark.anyio
async def test_resource_read_and_not_found(db):
    from mcp.shared.exceptions import MCPError
    async with Client(srv.build_server(db, with_auth=False)) as c:
        rr = await c.read_resource("spec://CHM-0420")
        assert json.loads(rr.contents[0].text)[0]["value"] == "180.5"
        assert rr.ttl_ms == 60_000 and rr.cache_scope == "private"
        with pytest.raises(MCPError) as ei:
            await c.read_resource("spec://NOPE-999")
    assert ei.value.error.code == -32602  # 2026-07-28: resource not found = Invalid Params


@pytest.mark.anyio
async def test_audit_is_metadata_only(db):
    srv.AUDIT_EVENTS.clear()
    async with Client(srv.build_server(db, with_auth=False)) as c:
        await c.call_tool("get_spec_value", {"part_id": "WFR-3001", "parameter": "max_bow"})
    ev = srv.AUDIT_EVENTS[-1]
    assert ev["tool"] == "get_spec_value" and ev["outcome"] == "ok" and "args_hash" in ev
    assert "WFR-3001" not in json.dumps(srv.AUDIT_EVENTS) and "40" != ev.get("value")


# ------------------------------------------------------------------ read-only, two layers
def test_credential_layer_is_read_only(db):
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ReadOnlyRepository(db).raw_connection_for_test().execute("DELETE FROM specs")


@pytest.mark.anyio
async def test_server_layer_exposes_only_read_only_tools(db):
    async with Client(srv.build_server(db, with_auth=False)) as c:
        tools = (await c.list_tools()).tools
    assert {t.name for t in tools} == {"get_spec_value", "search_procedures", "search_incidents"}
    assert all(t.annotations.read_only_hint and not t.annotations.destructive_hint for t in tools)


# ------------------------------------------------------------------ contract: tools/list snapshot
@pytest.mark.anyio
async def test_tools_list_snapshot(db):
    async with Client(srv.build_server(db, with_auth=False)) as c:
        tl = await c.list_tools()
    current = [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tl.tools]
    current = sorted(current, key=lambda t: t["name"])
    for t in current:
        t.pop("_meta", None)
    if os.environ.get("UPDATE_SNAPSHOTS") == "1" or not SNAPSHOT.exists():
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    assert current == json.loads(SNAPSHOT.read_text()), "tools/list contract changed: review + re-approve gateway pins"
    assert tl.ttl_ms == 300_000 and tl.cache_scope == "private"


@pytest.fixture()
def anyio_backend():
    return "asyncio"
