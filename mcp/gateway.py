"""MCP gateway policy layer (stdlib only; framework-agnostic policy decision point).

Sits between agents and approved MCP servers. Enforces:
  1. Server allowlist (+ EU-region pinning of each upstream)
  2. Tool allowlist with pinned SHA-256 of each tool definition (name, description,
     schemas, annotations). New/changed/removed tools => quarantine + alert
     ("rug pull" / tool poisoning defence). Only approved, unchanged tools are
     returned to the agent from tools/list.
  3. Per-tool scopes (gateway-side, independent of the upstream server's own checks)
  4. Header/body consistency (Mcp-Method / Mcp-Name, spec 2026-07-28) before
     routing on headers
  5. Injection screening hook on tool descriptions, arguments and results
     (pluggable: heuristic here; Model Armor / Bedrock Guardrails in prod)
  6. Per-(principal, tool) token-bucket rate limits
  7. Metadata-only audit of every decision
  8. No token passthrough: upstream calls carry the gateway's own token for the
     upstream audience, never the agent's inbound token.

The policy is plain data so it can be reviewed and version-controlled (policy-as-code),
analogous to an AgentCore Policy engine attached to an AgentCore Gateway.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

SUPPORTED_PROTOCOL_VERSIONS = {"2026-07-28"}  # versions whose header/body validation we rely on
EU_REGIONS = {"eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2",
              "europe-west1", "europe-west3", "europe-west4", "europe-west9", "europe-north1"}


# ------------------------------------------------------------------ hashing / pinning
def canonical_tool(tool: dict) -> dict:
    """Fields that influence model behaviour or call semantics. Excludes `_meta` (volatile)."""
    keep = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
    return {k: tool[k] for k in keep if k in tool}


def tool_hash(tool: dict) -> str:
    blob = json.dumps(canonical_tool(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    # NFC-normalise so visually identical text hashes identically; homoglyph/zero-width
    # changes still change the hash (and are flagged by the screener).
    return hashlib.sha256(unicodedata.normalize("NFC", blob).encode()).hexdigest()


# ------------------------------------------------------------------ screening hook
@dataclass
class Verdict:
    flagged: bool
    reasons: list[str] = field(default_factory=list)


class Screener(Protocol):
    def screen(self, text: str, *, direction: str) -> Verdict: ...


class HeuristicScreener:
    """Cheap first-pass detector. NOT a security boundary: paraphrased or encoded attacks
    will get through. Real enforcement = scopes, allowlists, read-only credentials.
    Production: call Model Armor (sanitizeUserPrompt/sanitizeModelResponse) or a Bedrock
    Guardrail (ApplyGuardrail, prompt-attack filter) from this hook."""

    PATTERNS = [
        (r"ignore (all )?(previous|prior|above) instructions", "override-instructions"),
        (r"disregard (the )?(system|previous) (prompt|instructions)", "override-instructions"),
        (r"\byou are now\b|\bnew instructions\b|\bsystem prompt\b", "role-hijack"),
        (r"\b(call|invoke|use) (the )?(tool|function)?\s*`?[a-z_]+`? (on|for) every\b", "tool-directive"),
        (r"\b(e-?mail|send|post|upload|exfiltrate)\b.{0,60}(@|https?://)", "exfiltration"),
        (r"<\s*(important|system|instructions?)\s*>", "hidden-tag"),
    ]
    INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤\U000e0000-\U000e007f]")

    def screen(self, text: str, *, direction: str) -> Verdict:
        reasons = [label for pat, label in self.PATTERNS if re.search(pat, text, re.I)]
        if self.INVISIBLE.search(text):
            reasons.append("invisible-unicode")
        return Verdict(bool(reasons), sorted(set(reasons)))


# ------------------------------------------------------------------ rate limiting
class TokenBucket:
    def __init__(self, capacity: int, refill_per_s: float, clock: Callable[[], float] = time.monotonic):
        self.capacity, self.refill, self.clock = capacity, refill_per_s, clock
        self.tokens, self.t = float(capacity), clock()

    def take(self) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.t) * self.refill)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


# ------------------------------------------------------------------ policy model
@dataclass
class ToolPolicy:
    scopes: set[str]
    pin: str | None = None          # sha256 of approved definition; None = not yet approved
    rate: tuple[int, float] = (30, 0.5)   # burst 30, 1 call / 2 s sustained per principal
    max_arg_bytes: int = 2048
    result_action: str = "flag"     # flag | redact | block when result screening fires


@dataclass
class ServerPolicy:
    url: str
    region: str
    audience: str                   # upstream canonical URI (token audience for that server)
    tools: dict[str, ToolPolicy]
    resource_prefixes: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class Decision:
    allow: bool
    status: int = 200
    reason: str = "ok"
    jsonrpc_code: int | None = None
    www_authenticate: str | None = None


@dataclass
class Principal:
    sub: str
    client_id: str
    scopes: set[str]
    agent_id: str = "unknown"


class Gateway:
    def __init__(self, servers: dict[str, ServerPolicy], *, screener: Screener | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 upstream_token_provider: Callable[[str], str] | None = None):
        for sid, sp in servers.items():
            if sp.region not in EU_REGIONS:
                raise ValueError(f"server {sid} is in non-EU region {sp.region}")
        self.servers = servers
        self.screener = screener or HeuristicScreener()
        self.clock = clock
        self.buckets: dict[tuple, TokenBucket] = {}
        self.quarantined: dict[tuple[str, str], str] = {}
        self.audit: list[dict] = []
        self.alerts: list[dict] = []
        # Gateway's OWN credential for each upstream audience (client_credentials / RFC 8693
        # token exchange / workload identity). Never the agent's inbound bearer token.
        self.upstream_token_provider = upstream_token_provider or (lambda aud: f"gw-token-for:{aud}")

    # ---------------------------------------------------------------- audit helpers
    def _audit(self, event: str, **kv) -> None:
        self.audit.append({"ts": round(self.clock(), 3), "event": event, **kv})

    def _alert(self, kind: str, **kv) -> None:
        rec = {"ts": round(self.clock(), 3), "alert": kind, **kv}
        self.alerts.append(rec)
        self._audit("alert", kind=kind, **kv)

    @staticmethod
    def _h(v: Any) -> str:
        return hashlib.sha256(json.dumps(v, sort_keys=True, default=str).encode()).hexdigest()[:16]

    # ---------------------------------------------------------------- approval workflow
    def approve(self, server_id: str, tools_list: list[dict]) -> dict[str, str]:
        """Human-reviewed approval step: pins hashes for allowlisted tools only.
        Returns a lockfile mapping tool -> sha256 (commit it next to the policy)."""
        sp = self.servers[server_id]
        lock = {}
        for t in tools_list:
            if t["name"] in sp.tools:
                v = self.screener.screen(t.get("description", ""), direction="tool_description")
                if v.flagged:
                    raise ValueError(f"refusing to pin {t['name']}: description flagged {v.reasons}")
                sp.tools[t["name"]].pin = lock[t["name"]] = tool_hash(t)
        return lock

    # ---------------------------------------------------------------- tools/list filter
    def filter_tools_list(self, server_id: str, tools_list: list[dict]) -> list[dict]:
        """Return only allowlisted tools whose definition still matches the pin."""
        sp = self.servers.get(server_id)
        if sp is None:
            self._alert("unapproved_server", server=server_id)
            return []
        seen, exposed = set(), []
        for t in tools_list:
            name = t.get("name", "")
            seen.add(name)
            pol = sp.tools.get(name)
            if pol is None:
                self._alert("tool_added_unapproved", server=server_id, tool=name, sha=tool_hash(t))
                continue
            h = tool_hash(t)
            if pol.pin is None or h != pol.pin:
                self.quarantined[(server_id, name)] = h
                self._alert("tool_definition_changed", server=server_id, tool=name, pinned=pol.pin, observed=h)
                continue
            v = self.screener.screen(json.dumps(canonical_tool(t)), direction="tool_description")
            if v.flagged:  # belt and braces: pinned yet suspicious (should have failed approval)
                self.quarantined[(server_id, name)] = h
                self._alert("tool_description_injection", server=server_id, tool=name, reasons=v.reasons)
                continue
            self.quarantined.pop((server_id, name), None)
            exposed.append(t)
        for name in set(sp.tools) - seen:
            self._alert("tool_removed", server=server_id, tool=name)
        self._audit("tools/list", server=server_id, offered=len(tools_list), exposed=len(exposed))
        return sorted(exposed, key=lambda t: t["name"])  # deterministic order (spec SHOULD)

    # ---------------------------------------------------------------- request authorization
    @staticmethod
    def _decode_header(v: str | None) -> str | None:
        if v and v.startswith("=?base64?") and v.endswith("?="):
            return base64.b64decode(v[9:-2]).decode()
        return v

    def authorize(self, principal: Principal, server_id: str, headers: dict[str, str], body: dict) -> Decision:
        h = {k.lower(): v for k, v in headers.items()}
        method = body.get("method", "")
        params = body.get("params") or {}
        name = params.get("name") or params.get("uri")
        base = dict(server=server_id, method=method, name=name, sub_hash=self._h(principal.sub),
                    client_id=principal.client_id, agent=principal.agent_id)

        def deny(status: int, reason: str, code: int | None = None, www: str | None = None) -> Decision:
            self._audit("deny", reason=reason, **base)
            return Decision(False, status, reason, code, www)

        if "authorization-upstream" in h:
            return deny(400, "client attempted to supply upstream credential")
        # 1. protocol version + header/body consistency (only trust headers we can validate)
        if h.get("mcp-protocol-version") not in SUPPORTED_PROTOCOL_VERSIONS:
            return deny(400, "unsupported or missing MCP-Protocol-Version")
        meta_ver = (params.get("_meta") or {}).get("io.modelcontextprotocol/protocolVersion")
        if meta_ver != h.get("mcp-protocol-version"):
            return deny(400, "protocol version header/body mismatch", -32020)
        if h.get("mcp-method") != method:
            return deny(400, "Mcp-Method header/body mismatch", -32020)
        if method in ("tools/call", "resources/read", "prompts/get") and self._decode_header(h.get("mcp-name")) != name:
            return deny(400, "Mcp-Name header/body mismatch", -32020)
        # 2. server allowlist
        sp = self.servers.get(server_id)
        if sp is None:
            return deny(403, "server not allowlisted")
        # 3. method-specific checks
        if method == "tools/call":
            pol = sp.tools.get(name or "")
            if pol is None:
                return deny(403, "tool not allowlisted")
            if pol.pin is None or (server_id, name) in self.quarantined:
                return deny(403, "tool quarantined (definition not approved or changed)")
            if not pol.scopes <= principal.scopes:
                return deny(403, "insufficient_scope", www=f'Bearer error="insufficient_scope", scope="{" ".join(sorted(pol.scopes))}"')
            args = params.get("arguments") or {}
            if len(json.dumps(args)) > pol.max_arg_bytes:
                return deny(413, "arguments too large")
            v = self.screener.screen(json.dumps(args), direction="tool_arguments")
            if v.flagged:
                self._alert("argument_injection", tool=name, reasons=v.reasons, **{k: base[k] for k in ("server", "sub_hash")})
                return deny(400, f"arguments flagged: {','.join(v.reasons)}")
            key = (principal.sub, server_id, name)
            b = self.buckets.setdefault(key, TokenBucket(*pol.rate, clock=self.clock))
            if not b.take():
                return deny(429, "rate limit exceeded")
            self._audit("allow", args_hash=self._h(args), **base)
            return Decision(True)
        if method == "resources/read":
            for prefix, scopes in sp.resource_prefixes.items():
                if (name or "").startswith(prefix):
                    if not scopes <= principal.scopes:
                        return deny(403, "insufficient_scope")
                    self._audit("allow", **base)
                    return Decision(True)
            return deny(403, "resource not allowlisted")
        if method in ("tools/list", "resources/list", "resources/templates/list", "server/discover"):
            self._audit("allow", **base)
            return Decision(True)
        return deny(403, f"method {method} not permitted through gateway")

    # ---------------------------------------------------------------- upstream request
    def upstream_headers(self, server_id: str, inbound_headers: dict[str, str]) -> dict[str, str]:
        """Forward only MCP routing headers; replace Authorization with the gateway's own
        upstream token (audience = upstream server). Inbound token is never forwarded."""
        sp = self.servers[server_id]
        fwd = {k: v for k, v in inbound_headers.items()
               if k.lower() in ("mcp-protocol-version", "mcp-method", "mcp-name", "content-type", "accept",
                                "traceparent", "tracestate") or k.lower().startswith("mcp-param-")}
        fwd["Authorization"] = f"Bearer {self.upstream_token_provider(sp.audience)}"
        return fwd

    # ---------------------------------------------------------------- result screening
    def screen_result(self, server_id: str, tool: str, result: dict) -> dict:
        """Treat tool output as untrusted data. Flag/redact/block on detected injection and
        wrap text in explicit data delimiters ("spotlighting") for the orchestrator."""
        pol = self.servers[server_id].tools[tool]
        texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        texts.append(json.dumps(result.get("structuredContent", {})))
        v = self.screener.screen("\n".join(texts), direction="tool_result")
        out = json.loads(json.dumps(result))
        meta = out.setdefault("_meta", {})
        meta["eu.example.gateway/untrusted"] = True
        if v.flagged:
            self._alert("result_injection", server=server_id, tool=tool, reasons=v.reasons, action=pol.result_action)
            meta["eu.example.gateway/injectionFlags"] = v.reasons
            if pol.result_action == "block":
                return {"content": [{"type": "text", "text": "Result withheld by gateway policy (suspected prompt injection)."}],
                        "isError": True, "_meta": meta}
            if pol.result_action == "redact":
                for c in out.get("content", []):
                    if c.get("type") == "text":
                        c["text"] = "[REDACTED: suspected prompt injection in source document]"
                out.pop("structuredContent", None)
        for c in out.get("content", []):
            if c.get("type") == "text":
                c["text"] = f"<untrusted_tool_output tool=\"{tool}\">\n{c['text']}\n</untrusted_tool_output>"
        self._audit("result", server=server_id, tool=tool, is_error=bool(result.get("isError")), flagged=v.flagged)
        return out
