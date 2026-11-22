"""Resource-server side of MCP authorization (spec 2026-07-28, basic/authorization).

What a protected MCP server MUST/SHOULD do, and where it is done here:
  * Publish OAuth 2.0 Protected Resource Metadata (RFC 9728)    -> SDK route via AuthSettings + prm_document()
  * Validate tokens per OAuth 2.1 sec 5.2: signature, exp, iss  -> JwtTokenVerifier.verify_token
  * Validate audience = this server's canonical URI (RFC 8707)  -> JwtTokenVerifier (aud check)
  * 401 + WWW-Authenticate: Bearer resource_metadata=..., scope -> SDK RequireAuthMiddleware / www_authenticate()
  * 403 insufficient_scope with scope=... for runtime scope gaps -> PerToolScopeMiddleware (server.py)
  * MUST NOT accept or transit other tokens (no passthrough)   -> downstream uses the server's own identity

Demo uses HS256 with a shared secret because no IdP is reachable offline.
PRODUCTION: asymmetric RS256/ES256 tokens from the EU IdP (e.g. Amazon Cognito
in eu-central-1, Entra ID EU, Keycloak on EU infra), keys fetched from the
issuer's jwks_uri (PyJWT: jwt.PyJWKClient), algorithms pinned, small leeway.
"""

from __future__ import annotations

import os
import time
from typing import Any

import jwt  # PyJWT 2.x (installed: 2.15.0)

from mcp.server.auth.provider import AccessToken, TokenVerifier

# ---- deployment constants (EU-only endpoints) -------------------------------------------
RESOURCE_URI = "https://eng-knowledge.mcp.eu-central-1.example.internal/mcp"  # canonical URI, no trailing slash
ISSUER = "https://idp.eu-central-1.example.internal"
# Demo/test signing key. Read from the environment; the fallback exists only so the offline
# tests run. Production uses asymmetric keys (RS256/ES256) fetched from the identity
# provider's JWKS endpoint, never a shared secret in code.
DEMO_SECRET = os.environ.get(
    "MCP_DEMO_HS256_SECRET",
    "demo-only-shared-secret-change-me-32bytes!",  # noqa: S105 - offline test fallback only
)
ALGORITHMS = ["HS256"]  # production: ["RS256"] or ["ES256"], never "none"

# ---- scope model: one read scope per data domain; no write scopes exist -----------------
TOOL_SCOPES: dict[str, set[str]] = {
    "get_spec_value": {"spec:read"},
    "search_procedures": {"procedures:read"},
    "search_incidents": {"incidents:read"},
}
RESOURCE_SCOPES: dict[str, set[str]] = {"spec://": {"spec:read"}}
SCOPE_HIERARCHY: dict[str, set[str]] = {
    # broader scope implies narrower ones (spec: servers MUST account for hierarchies)
    "eng:read": {"spec:read", "procedures:read", "incidents:read"},
}
SCOPES_SUPPORTED = ["spec:read", "procedures:read", "incidents:read"]


def expand_scopes(granted: set[str]) -> set[str]:
    out = set(granted)
    for s in granted:
        out |= SCOPE_HIERARCHY.get(s, set())
    return out


def required_scopes_for(method: str, name: str | None) -> set[str]:
    """Scopes needed for a JSON-RPC method/name. Discovery/list calls need only a valid token."""
    if method == "tools/call":
        # Unknown tool: demand an impossible scope -> fail closed (the gateway also blocks it).
        return TOOL_SCOPES.get(name or "", {"__unknown_tool__"})
    if method == "resources/read":
        for prefix, scopes in RESOURCE_SCOPES.items():
            if (name or "").startswith(prefix):
                return scopes
        return {"__unknown_resource__"}
    return set()


class JwtTokenVerifier(TokenVerifier):
    """SDK TokenVerifier that checks signature, exp/nbf/iat, iss and aud (RFC 8707)."""

    def __init__(self, *, secret: str = DEMO_SECRET, audience: str = RESOURCE_URI, issuer: str = ISSUER):
        self._secret = secret
        self._audience = audience
        self._issuer = issuer

    def decode(self, token: str) -> dict[str, Any] | None:
        try:
            return jwt.decode(
                token,
                self._secret,
                algorithms=ALGORITHMS,
                audience=self._audience,  # rejects tokens minted for another resource
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=30,
            )
        except jwt.PyJWTError:
            return None  # -> 401 invalid_token (no detail leaked to caller)

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = self.decode(token)
        if claims is None:
            return None
        raw = claims.get("scope") or claims.get("scp") or ""
        scopes = raw.split() if isinstance(raw, str) else list(raw)
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or "unknown"),
            scopes=sorted(expand_scopes(set(scopes))),
            expires_at=int(claims["exp"]),
            resource=self._audience,  # aud already verified == RESOURCE_URI
            subject=str(claims["sub"]),
            claims={"iss": claims["iss"]},
        )


def mint_demo_token(
    *,
    scopes: list[str],
    audience: str = RESOURCE_URI,
    issuer: str = ISSUER,
    sub: str = "user-123",
    client_id: str = "https://agents.example.eu/client-metadata.json",  # CIMD-style URL client_id
    ttl: int = 300,
    secret: str = DEMO_SECRET,
) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": issuer, "aud": audience, "sub": sub, "client_id": client_id,
         "scope": " ".join(scopes), "iat": now, "exp": now + ttl},
        secret,
        algorithm="HS256",
    )


def prm_document(resource: str = RESOURCE_URI) -> dict[str, Any]:
    """RFC 9728 Protected Resource Metadata (the SDK serves an equivalent document)."""
    return {
        "resource": resource,
        "authorization_servers": [ISSUER],
        "scopes_supported": SCOPES_SUPPORTED,
        "bearer_methods_supported": ["header"],
    }


def resource_metadata_url(resource: str = RESOURCE_URI) -> str:
    # RFC 9728 sec 3.1: well-known suffix inserted between host and path.
    scheme, rest = resource.split("://", 1)
    host, _, path = rest.partition("/")
    return f"{scheme}://{host}/.well-known/oauth-protected-resource" + (f"/{path}" if path else "")


def www_authenticate(error: str, scopes: set[str] | None = None, description: str | None = None) -> str:
    parts = [f'error="{error}"']
    if scopes:
        parts.append(f'scope="{" ".join(sorted(scopes))}"')
    parts.append(f'resource_metadata="{resource_metadata_url()}"')
    if description:
        parts.append(f'error_description="{description}"')
    return "Bearer " + ", ".join(parts)
