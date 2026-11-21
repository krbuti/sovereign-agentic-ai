"""
byom_gateway_v2.py - production-shaped Bring-Your-Own-Model (BYOM) gateway.

Agents never name a model. They ask for a ROLE ("router", "reasoning", "embedding");
the gateway resolves the role to the tenant's own model from config and enforces:

  region lock (EU only, endpoint-kind aware)  -> RegionPolicy
  eval gate (golden set passed, current ver.) -> ModelSpec.eval / ModelRegistry.activate
  capability check (ctx window, tools, ...)   -> Needs vs ModelSpec
  PII masking before any model sees text      -> LayeredMasker (reversible, number-safe)
  per-model circuit breaker                   -> CircuitBreaker
  retries: transient only, full jitter, cap,  -> RetryPolicy + RetryBudget (token bucket)
           per-attempt timeout, overall deadline
  fallback within EU only, each fallback must also pass the eval gate
  search-only degraded mode                   -> SearchOnlyMode exception
  token budget, atomic + shared               -> RedisBudgetStore (Lua) / InMemoryBudgetStore
  cost per TASK (not per token)               -> CostLedger
  latency SLO tracking (client + server TTFT) -> LatencyTracker
  audit: metadata only, never raw prompts     -> structured JSON logging + OpenTelemetry spans
  customer cloud identity, no static keys     -> AwsAssumeRole / AzureManagedIdentity / GcpWorkloadIdentity
  embedding model pinned to index version     -> IndexRegistry (blue-green, never mix vectors)

Runs with mocks and only the standard library (+ optional PyYAML, redis, opentelemetry-api).
    python3 byom_gateway_v2.py
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

try:  # OpenTelemetry API is optional; without an SDK configured it is a no-op tracer.
    from opentelemetry import trace as _otel_trace
    _TRACER = _otel_trace.get_tracer("byom.gateway")
except ImportError:  # pragma: no cover
    _TRACER = None

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    yaml = None


# =============================================================================
# 1. Error taxonomy: classify FIRST, then decide retry / fallback / degrade.
# =============================================================================
class GatewayError(Exception):
    """Base class."""

class TransientError(GatewayError):
    """Timeouts, throttling (429), 5xx, connection resets. Retry with backoff."""

class PermanentError(GatewayError):
    """4xx validation, auth, content filter, model not found. Never retry same call."""

class CircuitOpenError(TransientError):
    """Breaker is open for this model; skip without calling."""

class PolicyViolation(GatewayError):
    """Sovereignty / eval-gate / capability / index rule broken. Never silently bypassed."""

class SearchOnlyMode(GatewayError):
    """No eligible model could serve the call. Caller must answer with verbatim
    retrieved passages + links (no generation). `reason` is safe to log."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# =============================================================================
# 2. Contract types
# =============================================================================
@dataclass
class Needs:
    """Capabilities a call requires. Checked against the model BEFORE calling."""
    min_context: int = 0
    tool_calling: bool = False
    structured_output: bool = False
    table_understanding: bool = False

@dataclass
class ChatRequest:
    system: str
    messages: list[dict]
    max_tokens: int = 800
    temperature: float = 0.0
    needs: Needs = field(default_factory=Needs)

@dataclass
class ChatResponse:
    text: str
    input_tokens: int
    output_tokens: int
    model_id: str
    server_ttft_ms: Optional[float] = None   # provider-side, if the provider reports it
    degraded: bool = False

@dataclass
class EvalRecord:
    status: str = "pending"                  # pending | passed | failed
    golden_set_version: str = ""
    score: float = 0.0
    evaluated_at: str = ""

@dataclass
class ModelSpec:
    id: str
    provider: str                            # bedrock | azure_openai | vertex | openai_compat | mock
    model_ref: str                           # provider model id / profile id / deployment name (PINNED)
    endpoint_kind: str                       # regional | dedicated | geo_profile | data_zone | multi_region | global
    region: str                              # source/serving region, e.g. eu-west-1, europe-west4, swedencentral
    context_window: int = 8_000
    tool_calling: bool = False
    structured_output: bool = False
    table_understanding: bool = False
    kind: str = "chat"                       # chat | embedding
    embedding_dim: Optional[int] = None
    price_in_per_1k: float = 0.0             # EUR
    price_out_per_1k: float = 0.0
    timeout_s: float = 15.0
    slo_p95_ms: float = 4_000
    eval: EvalRecord = field(default_factory=EvalRecord)


# =============================================================================
# 3. Sovereignty: region policy that understands *endpoint kinds*.
#    A region string alone is not enough: Bedrock "eu." geo profiles, Azure EU Data
#    Zones and Vertex "eu" multi-region all route across several regions.
# =============================================================================
EU_MEMBER_STATE_REGIONS = {
    # AWS
    "eu-west-1", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1", "eu-south-2",
    # Google Cloud
    "europe-west1", "europe-west3", "europe-west4", "europe-west8", "europe-west9",
    "europe-north1", "europe-southwest1", "europe-central2",
    # Azure
    "swedencentral", "westeurope", "northeurope", "francecentral", "germanywestcentral",
    "italynorth", "polandcentral", "spaincentral",
}
# In Europe but NOT EU member states (UK, Switzerland, Norway): treat as non-EU.
EUROPE_NON_EU_REGIONS = {"eu-west-2", "eu-central-2", "europe-west2", "europe-west6",
                         "uksouth", "ukwest", "switzerlandnorth", "norwayeast"}

@dataclass
class TenantRegionPolicy:
    allowed_regions: set[str]
    eu_scope: str = "eu_member_states_only"  # or "eu_data_boundary" (permits EFTA, e.g. NO/CH)
    allow_eu_geo_routing: bool = True        # permit eu.* geo profiles / EU multi-region

    def check(self, m: ModelSpec) -> None:
        """Raise PolicyViolation if this model may process data outside the allowed scope."""
        if m.endpoint_kind == "global":
            raise PolicyViolation(f"{m.id}: global endpoint may process anywhere")
        if m.region in EUROPE_NON_EU_REGIONS:
            raise PolicyViolation(f"{m.id}: {m.region} is not an EU member-state region")
        if m.endpoint_kind in ("regional", "dedicated"):
            if m.region not in self.allowed_regions:
                raise PolicyViolation(f"{m.id}: region {m.region} not in tenant allowlist")
            return
        if m.endpoint_kind == "geo_profile":       # AWS Bedrock eu.* cross-region profile
            if not self.allow_eu_geo_routing or not m.model_ref.startswith("eu."):
                raise PolicyViolation(f"{m.id}: geo profile not permitted / not an eu.* profile")
            if m.region not in self.allowed_regions:   # source region must still be allowed
                raise PolicyViolation(f"{m.id}: source region {m.region} not allowed")
            return
        if m.endpoint_kind == "multi_region":      # Vertex 'eu' multi-region: EU member states only
            if not self.allow_eu_geo_routing or m.region != "eu":
                raise PolicyViolation(f"{m.id}: only the 'eu' multi-region is permitted")
            return
        if m.endpoint_kind == "data_zone":         # Azure EU Data Zone follows the EU Data Boundary
            if self.eu_scope != "eu_data_boundary":
                raise PolicyViolation(f"{m.id}: EU Data Zone may include EFTA regions; tenant "
                                      f"requires EU member states only")
            return
        raise PolicyViolation(f"{m.id}: unknown endpoint kind {m.endpoint_kind}")


# =============================================================================
# 4. PII masking: layered, reversible, and NUMBER-SAFE.
#    Spec values ("350 ± 5 °C", "0.8 mTorr", lot "L2026-0412") must never be masked,
#    otherwise the verifier's character-for-character number check breaks.
# =============================================================================
def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1

class LayeredMasker:
    """Layer 1: high-precision regex + validators. Layer 2: tenant dictionaries
    (operator roster, customer names). Layer 3: optional NER hook (Presidio,
    Amazon Comprehend DetectPiiEntities, Google Sensitive Data Protection)."""

    def __init__(self, person_names: tuple[str, ...] = (), employee_id_pattern: str = r"\bEMP-\d{6}\b",
                 ner_hook: Optional[Callable[[str], list[tuple[int, int, str]]]] = None):
        self.detectors: list[tuple[str, re.Pattern, Optional[Callable[[str], bool]]]] = [
            ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), None),
            # Phones only in clearly-phone formats (leading + and >= 9 digits), never bare numbers.
            ("PHONE", re.compile(r"\+\d{1,3}(?:[\s-]?\d){8,12}\b"), None),
            ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b"), _iban_ok),
            ("EMPLOYEE_ID", re.compile(employee_id_pattern), None),
        ]
        if person_names:
            names = "|".join(re.escape(n) for n in sorted(person_names, key=len, reverse=True))
            self.detectors.append(("PERSON", re.compile(rf"\b(?:{names})\b"), None))
        self.ner_hook = ner_hook

    def mask(self, text: str, vault: dict[str, str], counts: dict[str, int]) -> str:
        spans: list[tuple[int, int, str]] = []
        for label, rx, validator in self.detectors:
            for mt in rx.finditer(text):
                if validator is None or validator(mt.group(0)):
                    spans.append((mt.start(), mt.end(), label))
        if self.ner_hook:
            spans.extend(self.ner_hook(text))
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        out, pos = [], 0
        for start, end, label in spans:
            if start < pos:
                continue  # overlapping span already masked
            original = text[start:end]
            token = next((t for t, v in vault.items() if v == original), None)
            if token is None:
                counts[label] = counts.get(label, 0) + 1
                token = f"<{label}_{counts[label]}>"
                vault[token] = original
            out.append(text[pos:start]); out.append(token); pos = end
        out.append(text[pos:])
        return "".join(out)

    @staticmethod
    def unmask(text: str, vault: dict[str, str]) -> str:
        for token, original in vault.items():
            text = text.replace(token, original)
        return text


# =============================================================================
# 5. Resilience primitives
# =============================================================================
class CircuitBreaker:
    """closed -> open after `failure_threshold` transient failures within `window_s`;
    open -> half_open after `cooldown_s`; half_open lets `half_open_max` probes through."""

    def __init__(self, failure_threshold=5, window_s=60.0, cooldown_s=30.0, half_open_max=1,
                 clock: Callable[[], float] = time.monotonic):
        self.failure_threshold, self.window_s, self.cooldown_s = failure_threshold, window_s, cooldown_s
        self.half_open_max, self.clock = half_open_max, clock
        self.state, self.failures, self.opened_at, self.probes = "closed", deque(), 0.0, 0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = self.clock()
            if self.state == "open" and now - self.opened_at >= self.cooldown_s:
                self.state, self.probes = "half_open", 0
            if self.state == "open":
                return False
            if self.state == "half_open":
                if self.probes >= self.half_open_max:
                    return False
                self.probes += 1
            return True

    def record_success(self) -> None:
        with self._lock:
            self.state, self.probes = "closed", 0
            self.failures.clear()

    def record_failure(self) -> None:
        with self._lock:
            now = self.clock()
            if self.state == "half_open":
                self.state, self.opened_at = "open", now
                return
            self.failures.append(now)
            while self.failures and now - self.failures[0] > self.window_s:
                self.failures.popleft()
            if len(self.failures) >= self.failure_threshold:
                self.state, self.opened_at = "open", now


@dataclass
class RetryPolicy:
    max_attempts: int = 3          # total attempts per model (1 call + 2 retries)
    base_s: float = 0.2
    cap_s: float = 2.0

    def backoff(self, attempt: int, rng: random.Random) -> float:
        """'Full jitter': sleep = U(0, min(cap, base * 2**attempt))."""
        return rng.uniform(0.0, min(self.cap_s, self.base_s * (2 ** attempt)))


class RetryBudget:
    """Token bucket limiting retries process-wide (Builders' Library): retries flow
    freely while tokens remain, then at the refill rate. Stops retry storms."""

    def __init__(self, capacity=20.0, refill_per_s=1.0, clock=time.monotonic):
        self.capacity, self.refill, self.clock = capacity, refill_per_s, clock
        self.tokens, self.last = capacity, clock()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self.clock()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.refill)
            self.last = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


# =============================================================================
# 6. Token budget: reserve-then-reconcile, atomic, shared across replicas.
# =============================================================================
class BudgetStore(Protocol):
    def reserve(self, key: str, amount: int, limit: int, ttl_s: int) -> bool: ...
    def adjust(self, key: str, delta: int) -> int: ...
    def used(self, key: str) -> int: ...

class InMemoryBudgetStore:
    """Single-process fallback. NOT shared across replicas and lost on restart."""
    def __init__(self):
        self._v: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    def reserve(self, key, amount, limit, ttl_s):
        with self._lock:
            if self._v[key] + amount > limit:
                return False
            self._v[key] += amount
            return True
    def adjust(self, key, delta):
        with self._lock:
            self._v[key] = max(0, self._v[key] + delta)
            return self._v[key]
    def used(self, key):
        with self._lock:
            return self._v[key]

class RedisBudgetStore:
    """Atomic check-and-increment via a Lua script (runs atomically on the Redis server),
    so N gateway replicas cannot jointly overspend. Key: budget:{tenant}:{YYYY-MM}."""
    _RESERVE_LUA = """
    local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
    if cur + tonumber(ARGV[1]) > tonumber(ARGV[2]) then return -1 end
    local v = redis.call('INCRBY', KEYS[1], ARGV[1])
    if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[3]) end
    return v
    """
    def __init__(self, client):
        self.r = client
        self._reserve = client.register_script(self._RESERVE_LUA)
    def reserve(self, key, amount, limit, ttl_s):
        return int(self._reserve(keys=[key], args=[amount, limit, ttl_s])) >= 0
    def adjust(self, key, delta):
        return int(self.r.incrby(key, delta))
    def used(self, key):
        return int(self.r.get(key) or 0)

def make_budget_store() -> BudgetStore:
    url = os.environ.get("REDIS_URL")
    if url:
        try:
            import redis  # type: ignore
            client = redis.Redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5)
            client.ping()
            return RedisBudgetStore(client)
        except Exception as e:  # noqa: BLE001 - any Redis failure -> explicit, logged fallback
            logging.getLogger("byom.audit").warning(json.dumps(
                {"event": "budget_store_fallback", "reason": type(e).__name__}))
    return InMemoryBudgetStore()


# =============================================================================
# 7. Observability: latency SLOs, cost per task, audit (metadata only)
# =============================================================================
class LatencyTracker:
    """Rolling client-side latency + provider-side TTFT per model. p50/p95/p99."""
    def __init__(self, window=500, min_samples=20):
        self.lat: dict[str, deque] = defaultdict(lambda: deque(maxlen=window))
        self.ttft: dict[str, deque] = defaultdict(lambda: deque(maxlen=window))
        self.min_samples = min_samples
        self._lock = threading.Lock()

    def record(self, model_id: str, latency_ms: float, ttft_ms: Optional[float]) -> None:
        with self._lock:
            self.lat[model_id].append(latency_ms)
            if ttft_ms is not None:
                self.ttft[model_id].append(ttft_ms)

    @staticmethod
    def _pct(values, p: float) -> Optional[float]:
        if not values:
            return None
        s = sorted(values)
        k = max(0, min(len(s) - 1, math.ceil(p / 100 * len(s)) - 1))  # nearest-rank
        return s[k]

    def snapshot(self, model_id: str) -> dict:
        with self._lock:
            lat, tt = list(self.lat[model_id]), list(self.ttft[model_id])
        return {"n": len(lat), "p50_ms": self._pct(lat, 50), "p95_ms": self._pct(lat, 95),
                "p99_ms": self._pct(lat, 99), "server_ttft_p95_ms": self._pct(tt, 95)}

    def breaching(self, model_id: str, slo_p95_ms: float) -> bool:
        snap = self.snapshot(model_id)
        return snap["n"] >= self.min_samples and snap["p95_ms"] > slo_p95_ms


class CostLedger:
    """Cost per TASK (one user question = one agent run), not per token."""
    def __init__(self):
        self.tasks: dict[str, dict] = defaultdict(lambda: {"eur": 0.0, "calls": 0, "tokens": 0})
        self._lock = threading.Lock()
    def add(self, task_id: str, eur: float, tokens: int) -> None:
        with self._lock:
            t = self.tasks[task_id]
            t["eur"] += eur; t["calls"] += 1; t["tokens"] += tokens


class JsonFormatter(logging.Formatter):
    def format(self, record):  # the message is already a JSON object
        return record.getMessage()

def _audit_logger() -> logging.Logger:
    lg = logging.getLogger("byom.audit")
    if not lg.handlers:
        h = logging.StreamHandler()
        h.setFormatter(JsonFormatter())
        lg.addHandler(h)
        lg.setLevel(logging.INFO)
        lg.propagate = False
    return lg


# =============================================================================
# 8. Customer cloud identity (no static keys). Lazy imports; not executed in demo.
# =============================================================================
class AwsAssumeRoleCredentials:
    """Cross-account assume-role into the CUSTOMER's account with ExternalId.
    Short-lived (15 min), cached until 5 min before expiry. Bedrock calls are then
    billed to, logged in (CloudTrail), and governed by the customer's account."""
    def __init__(self, role_arn: str, external_id: str, region: str, session_name: str):
        self.role_arn, self.external_id, self.region, self.session_name = role_arn, external_id, region, session_name
        self._creds, self._exp = None, 0.0
    def session(self):
        import boto3
        if self._creds is None or time.time() > self._exp - 300:
            sts = boto3.client("sts", region_name=self.region,
                               endpoint_url=f"https://sts.{self.region}.amazonaws.com")  # regional STS
            out = sts.assume_role(RoleArn=self.role_arn, RoleSessionName=self.session_name,
                                  ExternalId=self.external_id, DurationSeconds=900)
            self._creds, self._exp = out["Credentials"], out["Credentials"]["Expiration"].timestamp()
        c = self._creds
        return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                             aws_session_token=c["SessionToken"], region_name=self.region)

class AzureManagedIdentity:
    """Entra ID token provider (managed identity / workload identity federation)."""
    def token_provider(self):
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        return get_bearer_token_provider(DefaultAzureCredential(),
                                         "https://cognitiveservices.azure.com/.default")

class GcpWorkloadIdentity:
    """Workload Identity Federation + service-account impersonation in the customer project."""
    def __init__(self, target_sa: str):
        self.target_sa = target_sa
    def credentials(self):
        import google.auth
        from google.auth import impersonated_credentials
        src, _ = google.auth.default()
        return impersonated_credentials.Credentials(
            source_credentials=src, target_principal=self.target_sa,
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"], lifetime=900)


# =============================================================================
# 9. Provider adapters. Real ones are lazy and NOT executed here (no network).
#    Every adapter: SDK-level retries DISABLED (retry at one layer only = gateway),
#    explicit timeout, and maps vendor errors onto Transient/Permanent.
# =============================================================================
class Provider(Protocol):
    def chat(self, spec: ModelSpec, req: ChatRequest, timeout_s: float) -> ChatResponse: ...
    def embed(self, spec: ModelSpec, texts: list[str], timeout_s: float) -> list[list[float]]: ...

_BEDROCK_TRANSIENT = {"ThrottlingException", "ServiceUnavailableException", "ModelTimeoutException",
                      "InternalServerException", "ModelNotReadyException"}

class BedrockConverseAdapter:
    def __init__(self, creds: AwsAssumeRoleCredentials):
        self.creds = creds
    def chat(self, spec, req, timeout_s):
        from botocore.config import Config
        from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError
        client = self.creds.session().client(
            "bedrock-runtime", region_name=spec.region,
            config=Config(connect_timeout=2, read_timeout=timeout_s, retries={"max_attempts": 1}))
        try:
            out = client.converse(
                modelId=spec.model_ref,  # e.g. an eu.* inference profile ID, version-pinned
                system=[{"text": req.system}],
                messages=[{"role": m["role"], "content": [{"text": m["content"]}]} for m in req.messages],
                inferenceConfig={"maxTokens": req.max_tokens, "temperature": req.temperature})
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            raise TransientError(type(e).__name__) from e
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            raise (TransientError if code in _BEDROCK_TRANSIENT else PermanentError)(code) from e
        return ChatResponse(out["output"]["message"]["content"][0]["text"],
                            out["usage"]["inputTokens"], out["usage"]["outputTokens"], spec.id,
                            server_ttft_ms=None)  # Converse returns metrics.latencyMs (total), not TTFT
    def embed(self, spec, texts, timeout_s):
        raise NotImplementedError("use bedrock-runtime invoke_model with the embedding model's body schema")

class AzureOpenAIAdapter:
    def __init__(self, endpoint: str, identity: AzureManagedIdentity, api_version: str):
        self.endpoint, self.identity, self.api_version = endpoint, identity, api_version
    def chat(self, spec, req, timeout_s):
        import openai
        client = openai.AzureOpenAI(azure_endpoint=self.endpoint, api_version=self.api_version,
                                    azure_ad_token_provider=self.identity.token_provider(),
                                    timeout=timeout_s, max_retries=0)
        try:
            r = client.chat.completions.create(
                model=spec.model_ref,  # deployment name; deployment type DataZoneStandard (EU)
                messages=[{"role": "system", "content": req.system}, *req.messages],
                max_tokens=req.max_tokens, temperature=req.temperature)
        except (openai.APITimeoutError, openai.APIConnectionError, openai.RateLimitError,
                openai.InternalServerError) as e:
            raise TransientError(type(e).__name__) from e
        except openai.APIStatusError as e:
            raise PermanentError(f"HTTP {e.status_code}") from e
        return ChatResponse(r.choices[0].message.content, r.usage.prompt_tokens,
                            r.usage.completion_tokens, spec.id)
    def embed(self, spec, texts, timeout_s):
        raise NotImplementedError

class VertexAdapter:
    def __init__(self, project: str, identity: GcpWorkloadIdentity):
        self.project, self.identity = project, identity
    def chat(self, spec, req, timeout_s):
        from google import genai
        from google.genai import types
        client = genai.Client(vertexai=True, project=self.project, location=spec.region,  # 'europe-west4' or 'eu'
                              credentials=self.identity.credentials(),
                              http_options=types.HttpOptions(timeout=int(timeout_s * 1000)))
        r = client.models.generate_content(
            model=spec.model_ref, contents=[m["content"] for m in req.messages],
            config=types.GenerateContentConfig(system_instruction=req.system,
                                               max_output_tokens=req.max_tokens, temperature=req.temperature))
        u = r.usage_metadata
        return ChatResponse(r.text, u.prompt_token_count, u.candidates_token_count, spec.id)
    def embed(self, spec, texts, timeout_s):
        raise NotImplementedError

class OpenAICompatibleAdapter:
    """vLLM / SGLang / TGI on DEDICATED EU GPUs (open-weight model, pinned weights hash)."""
    def __init__(self, base_url: str, token_provider: Callable[[], str]):
        self.base_url, self.token_provider = base_url.rstrip("/"), token_provider
    def chat(self, spec, req, timeout_s):
        import requests
        try:
            r = requests.post(f"{self.base_url}/v1/chat/completions", timeout=(2, timeout_s),
                              headers={"Authorization": f"Bearer {self.token_provider()}"},
                              json={"model": spec.model_ref,
                                    "messages": [{"role": "system", "content": req.system}, *req.messages],
                                    "max_tokens": req.max_tokens, "temperature": req.temperature})
        except (requests.Timeout, requests.ConnectionError) as e:
            raise TransientError(type(e).__name__) from e
        if r.status_code == 429 or r.status_code >= 500:
            raise TransientError(f"HTTP {r.status_code}")
        if r.status_code >= 400:
            raise PermanentError(f"HTTP {r.status_code}")
        d = r.json()
        return ChatResponse(d["choices"][0]["message"]["content"], d["usage"]["prompt_tokens"],
                            d["usage"]["completion_tokens"], spec.id)
    def embed(self, spec, texts, timeout_s):
        raise NotImplementedError


class MockProvider:
    """Deterministic test double. Script failures per model: a list of 'transient',
    'permanent', 'slow' or 'ok' consumed one per call. Records what it received so
    tests can prove PII never reached the model."""
    def __init__(self, responder: Optional[Callable[[ModelSpec, ChatRequest], str]] = None):
        self.script: dict[str, list[str]] = defaultdict(list)
        self.received: list[tuple[str, str]] = []
        self.latency_ms: dict[str, float] = defaultdict(lambda: 120.0)
        self.responder = responder or (lambda spec, req: f"[{spec.id}] {req.messages[-1]['content'][:60]}")

    def _next(self, spec, timeout_s):
        action = self.script[spec.id].pop(0) if self.script[spec.id] else "ok"
        if action == "transient":
            raise TransientError("ThrottlingException")
        if action == "permanent":
            raise PermanentError("ValidationException")
        if action == "slow" or self.latency_ms[spec.id] / 1000 > timeout_s:
            raise TransientError("ReadTimeout")

    def chat(self, spec, req, timeout_s):
        self._next(spec, timeout_s)
        self.received.append((spec.id, req.system + "\n" + "\n".join(m["content"] for m in req.messages)))
        text = self.responder(spec, req)
        prompt = req.system + " ".join(m["content"] for m in req.messages)
        return ChatResponse(text, max(1, len(prompt) // 4), max(1, len(text) // 4), spec.id,
                            server_ttft_ms=self.latency_ms[spec.id] * 0.3)

    def embed(self, spec, texts, timeout_s):
        self._next(spec, timeout_s)
        dim = spec.embedding_dim or 8
        return [[(hash((t, i)) % 1000) / 1000 for i in range(dim)] for t in texts]


# =============================================================================
# 10. Registry, eval gate, index registry
# =============================================================================
@dataclass
class RoleBinding:
    primary: str
    fallbacks: list[str] = field(default_factory=list)
    fallback_policy: str = "eu_only"         # eu_only | same_region_only | search_only

@dataclass
class TenantConfig:
    id: str
    home_region: str
    region_policy: TenantRegionPolicy
    roles: dict[str, RoleBinding]
    monthly_token_budget: int
    request_deadline_s: float = 20.0
    index_embedding_model: str = ""
    index_version: str = ""
    identity: dict = field(default_factory=dict)


class ModelRegistry:
    def __init__(self, models: dict[str, ModelSpec], golden_set_version: str, eval_threshold: float):
        self.models, self.golden_set_version, self.eval_threshold = models, golden_set_version, eval_threshold

    def eval_ok(self, m: ModelSpec) -> bool:
        e = m.eval
        return (e.status == "passed" and e.golden_set_version == self.golden_set_version
                and e.score >= self.eval_threshold)

    def activate(self, model_id: str, score: float, golden_set_version: str, when: str) -> bool:
        """The ONLY way a model becomes eligible. Fallback models go through this too."""
        ok = golden_set_version == self.golden_set_version and score >= self.eval_threshold
        self.models[model_id].eval = EvalRecord("passed" if ok else "failed", golden_set_version, score, when)
        return ok


def run_golden_set(gw: "Gateway", tenant_id: str, model_id: str,
                   golden: list[dict], scorer: Callable[[str, dict], float]) -> float:
    """Run the tenant's private golden set directly against ONE candidate model
    (bypassing role resolution and the eval gate itself). Returns mean score."""
    spec = gw.registry.models[model_id]
    scores = []
    for case in golden:
        req = ChatRequest(system=case["system"], messages=[{"role": "user", "content": case["question"]}])
        resp = gw.provider_for(spec).chat(spec, req, spec.timeout_s)
        scores.append(scorer(resp.text, case))
    return sum(scores) / len(scores)


class IndexRegistry:
    """Vectors from two embedding models are never mixed. Changing the embedding model
    = build a NEW index version, eval it, then flip the alias (blue-green). Rollback =
    flip back. The query-time embedding model must match the active index's model."""
    def __init__(self):
        self.versions: dict[str, dict] = {}
        self.active: dict[str, str] = {}      # tenant -> index version

    def register(self, version: str, embedding_model: str, dim: int):
        self.versions[version] = {"embedding_model": embedding_model, "dim": dim, "eval_passed": False}

    def mark_eval(self, version: str, passed: bool):
        self.versions[version]["eval_passed"] = passed

    def switch(self, tenant: str, version: str):
        if not self.versions[version]["eval_passed"]:
            raise PolicyViolation(f"index {version} has not passed retrieval eval")
        self.active[tenant] = version

    def assert_compatible(self, tenant: str, embedding_model: str):
        v = self.active.get(tenant)
        if v is None or self.versions[v]["embedding_model"] != embedding_model:
            raise PolicyViolation(f"embedding model {embedding_model} does not match active index {v}; "
                                  f"re-index required (never mix vectors)")


def load_config(text: str) -> tuple[ModelRegistry, dict[str, TenantConfig]]:
    if yaml is None:
        raise RuntimeError("PyYAML required to load YAML config")
    raw = yaml.safe_load(text)
    models = {}
    for mid, m in raw["models"].items():
        ev = EvalRecord(**m.pop("eval", {}))
        models[mid] = ModelSpec(id=mid, eval=ev, **m)
    registry = ModelRegistry(models, raw["golden_set_version"], raw["eval_threshold"])
    tenants = {}
    for tid, t in raw["tenants"].items():
        rp = TenantRegionPolicy(set(t["allowed_regions"]), t.get("eu_scope", "eu_member_states_only"),
                                t.get("allow_eu_geo_routing", True))
        roles = {r: RoleBinding(**b) for r, b in t["roles"].items()}
        tenants[tid] = TenantConfig(tid, t["region"], rp, roles, t["monthly_token_budget"],
                                    t.get("request_deadline_s", 20.0), t["index"]["embedding_model"],
                                    t["index"]["index_version"], t.get("identity", {}))
    return registry, tenants


# =============================================================================
# 11. The gateway
# =============================================================================
class Gateway:
    def __init__(self, registry: ModelRegistry, tenants: dict[str, TenantConfig],
                 providers: dict[str, Provider], masker: Optional[LayeredMasker] = None,
                 budget: Optional[BudgetStore] = None, retry: RetryPolicy = RetryPolicy(),
                 retry_budget: Optional[RetryBudget] = None, index_registry: Optional[IndexRegistry] = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 rng: Optional[random.Random] = None, breaker_factory: Optional[Callable[[], CircuitBreaker]] = None):
        self.registry, self.tenants, self.providers = registry, tenants, providers
        self.masker = masker or LayeredMasker()
        self.budget = budget or make_budget_store()
        self.retry, self.retry_budget = retry, retry_budget or RetryBudget(clock=clock)
        self.indexes = index_registry
        self.clock, self.sleep, self.rng = clock, sleep, rng or random.Random()
        self._breaker_factory = breaker_factory or (lambda: CircuitBreaker(clock=clock))
        self.breakers: dict[str, CircuitBreaker] = {}
        self.latency, self.costs, self.audit_log = LatencyTracker(), CostLedger(), _audit_logger()

    # --- helpers --------------------------------------------------------------
    def provider_for(self, spec: ModelSpec) -> Provider:
        return self.providers[spec.provider]

    def breaker(self, model_id: str) -> CircuitBreaker:
        if model_id not in self.breakers:
            self.breakers[model_id] = self._breaker_factory()
        return self.breakers[model_id]

    def _audit(self, **event) -> None:
        event.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self.audit_log.info(json.dumps(event, default=str, sort_keys=True))

    @staticmethod
    def _budget_key(tenant: str) -> str:
        return f"budget:{tenant}:{time.strftime('%Y-%m', time.gmtime())}"

    def _candidates(self, t: TenantConfig, role: str) -> list[tuple[ModelSpec, bool]]:
        b = t.roles[role]
        ids = [b.primary] + ([] if b.fallback_policy == "search_only" else b.fallbacks)
        return [(self.registry.models[i], i == b.primary) for i in ids]

    def _eligibility(self, t: TenantConfig, role: str, m: ModelSpec, is_primary: bool,
                     needs: Needs, est_tokens: int) -> Optional[str]:
        """Return a reason string if ineligible, else None."""
        try:
            t.region_policy.check(m)
        except PolicyViolation as e:
            return f"region:{e}"
        b = t.roles[role]
        primary = self.registry.models[b.primary]
        if not is_primary and b.fallback_policy == "same_region_only" and \
                (m.region != primary.region or m.endpoint_kind not in ("regional", "dedicated")):
            return "fallback_policy:same_region_only"
        if not self.registry.eval_ok(m):
            return f"eval_gate:{m.eval.status}@{m.eval.golden_set_version or 'none'}"
        if m.context_window < max(needs.min_context, est_tokens):
            return f"capability:context_window {m.context_window} < {max(needs.min_context, est_tokens)}"
        for cap in ("tool_calling", "structured_output", "table_understanding"):
            if getattr(needs, cap) and not getattr(m, cap):
                return f"capability:{cap}"
        return None

    # --- chat -----------------------------------------------------------------
    def chat(self, tenant_id: str, role: str, req: ChatRequest, task_id: str = "-",
             trace_id: Optional[str] = None) -> ChatResponse:
        t = self.tenants[tenant_id]
        trace_id = trace_id or uuid.uuid4().hex
        deadline = self.clock() + t.request_deadline_s
        span_cm = _TRACER.start_as_current_span("gateway.chat") if _TRACER else _NullCtx()
        with span_cm as span:
            _set(span, {"byom.tenant": tenant_id, "byom.role": role, "byom.trace_id": trace_id})

            # Mask ONCE, before any model (primary or fallback) sees the text.
            vault, counts = {}, {}
            masked = ChatRequest(self.masker.mask(req.system, vault, counts),
                                 [{**m, "content": self.masker.mask(m["content"], vault, counts)} for m in req.messages],
                                 req.max_tokens, req.temperature, req.needs)
            prompt_text = masked.system + "".join(m["content"] for m in masked.messages)
            est_in = max(1, len(prompt_text) // 4)    # use provider token counting in production
            base = dict(trace_id=trace_id, tenant=tenant_id, role=role, task_id=task_id,
                        prompt_sha256=hashlib.sha256(prompt_text.encode()).hexdigest()[:16],
                        pii_masked=counts, golden_set=self.registry.golden_set_version)

            # Budget: reserve worst case (input + max output) atomically, reconcile after.
            reserve = est_in + masked.max_tokens
            bkey = self._budget_key(tenant_id)
            if not self.budget.reserve(bkey, reserve, t.monthly_token_budget, 40 * 86400):
                self._audit(**base, event="budget_exhausted")
                raise SearchOnlyMode("token_budget_exhausted")

            candidates = self._candidates(t, role)
            # Soft SLO-aware ordering: models breaching p95 SLO move behind healthy ones.
            candidates.sort(key=lambda c: (self.latency.breaching(c[0].id, c[0].slo_p95_ms), not c[1]))
            last_reason = "no_candidates"
            for m, is_primary in candidates:
                why = self._eligibility(t, role, m, is_primary, masked.needs, est_in + masked.max_tokens)
                if why:
                    self._audit(**base, event="skip", model=m.id, region=m.region, reason=why)
                    last_reason = why
                    continue
                br = self.breaker(m.id)
                for attempt in range(self.retry.max_attempts):
                    remaining = deadline - self.clock()
                    if remaining <= 0:
                        self.budget.adjust(bkey, -reserve)
                        self._audit(**base, event="deadline_exceeded", model=m.id)
                        raise SearchOnlyMode("deadline_exceeded")
                    if not br.allow():
                        self._audit(**base, event="skip", model=m.id, reason=f"circuit_{br.state}")
                        last_reason = "circuit_open"
                        break
                    t0 = self.clock()
                    try:
                        resp = self.provider_for(m).chat(m, masked, min(m.timeout_s, remaining))
                    except TransientError as e:
                        br.record_failure()
                        last_reason = f"transient:{e}"
                        self._audit(**base, event="attempt_failed", model=m.id, attempt=attempt,
                                    error_class="transient", error=str(e), breaker=br.state)
                        if attempt + 1 < self.retry.max_attempts and self.retry_budget.try_acquire():
                            delay = self.retry.backoff(attempt, self.rng)
                            if self.clock() + delay < deadline:
                                self.sleep(delay)
                                continue
                        break                                   # -> next candidate
                    except PermanentError as e:                 # not a health signal: no breaker trip
                        last_reason = f"permanent:{e}"
                        self._audit(**base, event="attempt_failed", model=m.id, attempt=attempt,
                                    error_class="permanent", error=str(e))
                        break
                    # success
                    br.record_success()
                    latency_ms = (self.clock() - t0) * 1000
                    self.latency.record(m.id, latency_ms, resp.server_ttft_ms)
                    actual = resp.input_tokens + resp.output_tokens
                    self.budget.adjust(bkey, actual - reserve)
                    eur = resp.input_tokens / 1000 * m.price_in_per_1k + resp.output_tokens / 1000 * m.price_out_per_1k
                    self.costs.add(task_id, eur, actual)
                    self._audit(**base, event="ok", model=m.id, model_ref=m.model_ref, provider=m.provider,
                                region=m.region, endpoint_kind=m.endpoint_kind, fallback=not is_primary,
                                attempt=attempt, latency_ms=round(latency_ms, 1),
                                server_ttft_ms=resp.server_ttft_ms, input_tokens=resp.input_tokens,
                                output_tokens=resp.output_tokens, cost_eur=round(eur, 6),
                                slo_breach=self.latency.breaching(m.id, m.slo_p95_ms))
                    _set(span, {"gen_ai.request.model": m.model_ref, "gen_ai.provider.name": m.provider,
                                "gen_ai.usage.input_tokens": resp.input_tokens,
                                "gen_ai.usage.output_tokens": resp.output_tokens, "byom.fallback": not is_primary})
                    resp.text = self.masker.unmask(resp.text, vault)   # restore for the end user only
                    return resp
            self.budget.adjust(bkey, -reserve)          # release unused reservation
            self._audit(**base, event="search_only", reason=last_reason)
            raise SearchOnlyMode(last_reason)

    # --- embeddings: pinned to the index, never falls back to another model ---
    def embed(self, tenant_id: str, texts: list[str], trace_id: Optional[str] = None) -> list[list[float]]:
        t = self.tenants[tenant_id]
        m = self.registry.models[t.roles["embedding"].primary]
        if self.indexes:
            self.indexes.assert_compatible(tenant_id, m.id)
        why = self._eligibility(t, "embedding", m, True, Needs(), 0)
        if why:
            raise PolicyViolation(why)
        br = self.breaker(m.id)
        for attempt in range(self.retry.max_attempts):
            if not br.allow():
                break
            try:
                out = self.provider_for(m).embed(m, texts, m.timeout_s)
                br.record_success()
                return out
            except TransientError:
                br.record_failure()
                if attempt + 1 < self.retry.max_attempts and self.retry_budget.try_acquire():
                    self.sleep(self.retry.backoff(attempt, self.rng))
            except PermanentError:
                break
        self._audit(trace_id=trace_id, tenant=tenant_id, role="embedding", event="search_only",
                    reason="embedding_unavailable_lexical_fallback")
        raise SearchOnlyMode("embedding_unavailable")   # caller falls back to lexical (BM25) retrieval


class _NullCtx:
    def __enter__(self): return None
    def __exit__(self, *a): return False

def _set(span, attrs: dict) -> None:
    if span is not None and hasattr(span, "set_attributes"):
        span.set_attributes({k: v for k, v in attrs.items() if v is not None})


# =============================================================================
# 12. Example tenant config (fab-eu). Model refs are PLACEHOLDERS: resolve real,
#     version-pinned IDs with `aws bedrock list-inference-profiles --region eu-west-1`,
#     Azure deployment names, Vertex model versions.
# =============================================================================
EXAMPLE_CONFIG = """
golden_set_version: gs-2026-11-01
eval_threshold: 0.90
models:
  claude-haiku-eu:        {provider: mock, model_ref: "eu.anthropic.claude-haiku-PINNED-v1:0", endpoint_kind: geo_profile,
                           region: eu-west-1, context_window: 200000, tool_calling: true, structured_output: true,
                           price_in_per_1k: 0.0009, price_out_per_1k: 0.0045, slo_p95_ms: 1500,
                           eval: {status: passed, golden_set_version: gs-2026-11-01, score: 0.93}}
  mistral-small-dedicated: {provider: mock, model_ref: "mistral-small-PINNED@sha256:abcd", endpoint_kind: dedicated,
                           region: eu-central-1, context_window: 32000, tool_calling: true, structured_output: true,
                           price_in_per_1k: 0.0002, price_out_per_1k: 0.0006, slo_p95_ms: 1200,
                           eval: {status: passed, golden_set_version: gs-2026-11-01, score: 0.91}}
  claude-sonnet-eu:       {provider: mock, model_ref: "eu.anthropic.claude-sonnet-PINNED-v1:0", endpoint_kind: geo_profile,
                           region: eu-west-1, context_window: 200000, tool_calling: true, structured_output: true,
                           table_understanding: true, price_in_per_1k: 0.0028, price_out_per_1k: 0.014, slo_p95_ms: 6000,
                           eval: {status: passed, golden_set_version: gs-2026-11-01, score: 0.96}}
  llama-dedicated-eu:     {provider: mock, model_ref: "llama-PINNED@sha256:ef01", endpoint_kind: dedicated,
                           region: eu-west-1, context_window: 128000, tool_calling: true, structured_output: true,
                           table_understanding: true, price_in_per_1k: 0.0004, price_out_per_1k: 0.0012, slo_p95_ms: 5000,
                           eval: {status: pending}}
  gpt-azure-dz-eu:        {provider: mock, model_ref: "gpt-deployment-dzs-eu", endpoint_kind: data_zone,
                           region: swedencentral, context_window: 128000, tool_calling: true, structured_output: true,
                           table_understanding: true, price_in_per_1k: 0.0025, price_out_per_1k: 0.01, slo_p95_ms: 6000,
                           eval: {status: passed, golden_set_version: gs-2026-11-01, score: 0.94}}
  qwen-dedicated-eu-c1:   {provider: mock, model_ref: "qwen-PINNED@sha256:9a9a", endpoint_kind: dedicated,
                           region: eu-central-1, context_window: 128000, tool_calling: true, structured_output: true,
                           table_understanding: true, price_in_per_1k: 0.0003, price_out_per_1k: 0.0009, slo_p95_ms: 5000,
                           eval: {status: passed, golden_set_version: gs-2026-11-01, score: 0.92}}
  gemini-global:          {provider: mock, model_ref: "gemini-PINNED", endpoint_kind: global, region: global,
                           context_window: 1000000, tool_calling: true, structured_output: true, table_understanding: true,
                           eval: {status: passed, golden_set_version: gs-2026-11-01, score: 0.97}}
  titan-embed-eu:         {provider: mock, model_ref: "amazon.titan-embed-text-PINNED", endpoint_kind: regional,
                           region: eu-west-1, kind: embedding, embedding_dim: 8, context_window: 8000,
                           eval: {status: passed, golden_set_version: gs-2026-11-01, score: 0.95}}
tenants:
  fab-eu:
    region: eu-west-1
    eu_scope: eu_member_states_only
    allow_eu_geo_routing: true
    allowed_regions: [eu-west-1, eu-central-1, eu-west-3]
    monthly_token_budget: 2000000
    request_deadline_s: 20
    identity: {type: aws_assume_role, role_arn: "arn:aws:iam::111122223333:role/byom-invoke", external_id_ref: "secrets:fab-eu/external-id"}
    index: {embedding_model: titan-embed-eu, index_version: idx-v3-titan}
    roles:
      router:    {primary: claude-haiku-eu, fallbacks: [mistral-small-dedicated], fallback_policy: eu_only}
      reasoning: {primary: claude-sonnet-eu, fallbacks: [llama-dedicated-eu, gpt-azure-dz-eu, gemini-global, qwen-dedicated-eu-c1], fallback_policy: eu_only}
      embedding: {primary: titan-embed-eu, fallbacks: [], fallback_policy: search_only}
"""


def build_demo_gateway(responder=None, budget_tokens: Optional[int] = None, seed: int = 7,
                       sleep: Callable[[float], None] = lambda s: None):
    registry, tenants = load_config(EXAMPLE_CONFIG)
    if budget_tokens is not None:
        tenants["fab-eu"].monthly_token_budget = budget_tokens
    mock = MockProvider(responder)
    idx = IndexRegistry()
    idx.register("idx-v3-titan", "titan-embed-eu", 8); idx.mark_eval("idx-v3-titan", True)
    idx.switch("fab-eu", "idx-v3-titan")
    masker = LayeredMasker(person_names=("Jane Murphy", "Tomasz Nowak"))
    gw = Gateway(registry, tenants, {"mock": mock}, masker=masker, budget=InMemoryBudgetStore(),
                 index_registry=idx, rng=random.Random(seed), sleep=sleep)
    return gw, mock


if __name__ == "__main__":
    gw, mock = build_demo_gateway()
    q = ChatRequest(system="You answer from approved fab documents only.",
                    messages=[{"role": "user", "content":
                               "Jane Murphy (jane.murphy@fab.example, +353 89 123 4567, EMP-004211) asks: "
                               "is 350 ± 5 °C the anneal limit for lot L2026-0412?"}],
                    needs=Needs(table_understanding=True))
    print("== 1. primary flaky (2 throttles) -> retried with full jitter, succeeds ==")
    mock.script["claude-sonnet-eu"] = ["transient", "transient"]
    print(gw.chat("fab-eu", "reasoning", q, task_id="task-1").text)
    print("\n== 2. primary hard down -> pending-eval llama skipped, Azure DZ rejected (EFTA), "
          "global rejected, EU qwen serves ==")
    mock.script["claude-sonnet-eu"] = ["transient"] * 3
    print(gw.chat("fab-eu", "reasoning", q, task_id="task-2").text)
    print("\n== 3. everything down -> search-only ==")
    mock.script["claude-sonnet-eu"] = ["transient"] * 3
    mock.script["qwen-dedicated-eu-c1"] = ["transient"] * 3
    try:
        gw.chat("fab-eu", "reasoning", q, task_id="task-3")
    except SearchOnlyMode as e:
        print("SearchOnlyMode:", e.reason)
    print("\nWhat the model actually received (PII masked, numbers intact):")
    print(mock.received[0][1].splitlines()[-1])
    print("\nCost per task:", {k: {**v, "eur": round(v["eur"], 6)} for k, v in gw.costs.tasks.items()})
    print("Latency snapshot claude-sonnet-eu:", gw.latency.snapshot("claude-sonnet-eu"))
