import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore", category=DeprecationWarning)

from datastore import seed  # noqa: E402

HOST = "https://eng-knowledge.mcp.eu-central-1.example.internal"
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "pytest-agent", "version": "1.0"},
}


@pytest.fixture()
def db(tmp_path):
    p = tmp_path / "eng.db"
    seed(p)
    return p


def rpc(method: str, params: dict | None = None, *, name_header: str | None = "auto", rid: int = 1):
    """Build a 2026-07-28 Streamable HTTP request: _meta envelope + routing headers."""
    p = dict(params or {})
    p["_meta"] = MODERN_META
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if name_header == "auto":
        name_header = p.get("name") or p.get("uri")
    if name_header:
        headers["Mcp-Name"] = name_header
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": p}, headers
