"""AI anomaly detection. Uses Gemini 2.5 Flash (free tier) with structured JSON output.
Falls back to a local heuristic analyser if no API key is configured or the API errors,
so the POC always stays runnable."""
import base64
import json
import re
from typing import Any

from . import config
from .models import RequestSnapshot, Verdict

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "malicious": {"type": "boolean"},
        "threat_type": {
            "type": "string",
            "enum": [
                "none", "mass_assignment", "bola_idor", "privilege_escalation",
                "encoded_payload", "ssrf", "prompt_injection", "data_exfiltration",
                "business_logic_abuse", "other",
            ],
        },
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
    },
    "required": ["malicious", "threat_type", "confidence", "reason"],
}

_SYSTEM_PROMPT = """You are API-Guardian, a security analyst reviewing a single HTTP request to a REST API
before it reaches the backend. Obvious SQLi/XSS/path traversal has ALREADY been filtered by regex.
Your job is to spot SUBTLE, CONTEXTUAL anomalies, for example:
- Mass assignment / privilege escalation: a normal user endpoint receiving fields like is_admin, role,
  balance, verified, permissions, credit that clients should never set.
- Broken object level authorization (BOLA/IDOR): request referencing another user's id or a
  user_id/account_id in body/query that conflicts with the authenticated user (X-User-Id header),
  or negative/huge/wildcard identifiers.
- Encoded or obfuscated payloads: base64/hex/unicode-escaped strings that decode to code, SQL or shell.
- Business-logic abuse: negative transfer amounts, absurd amounts, transferring to self, etc.
- SSRF: URLs pointing at localhost, 169.254.169.254, internal hostnames.
Be precise. Normal CRUD traffic with ordinary fields (username, email, password, amount within reason)
is SAFE. Do not flag requests merely because they contain a password field or an email.
Respond ONLY with JSON matching the schema."""

_client = None


def _get_client():
    global _client
    if _client is None:
        from google import genai  # lazy import so offline mode never needs the SDK to load
        _client = genai.Client(api_key=config.GEMINI_API_KEY)
    return _client


def _describe(req: RequestSnapshot) -> str:
    safe_headers = {k: v for k, v in req.headers.items()
                    if k in ("content-type", "x-user-id", "x-role", "user-agent", "authorization", "referer")}
    if "authorization" in safe_headers:
        safe_headers["authorization"] = safe_headers["authorization"][:12] + "...(redacted)"
    body = req.body_json if req.body_json is not None else req.body_text[:2000]
    return json.dumps({
        "method": req.method,
        "path": req.path,
        "query": req.query,
        "headers": safe_headers,
        "body": body,
    }, indent=2, default=str)


async def analyze_with_gemini(req: RequestSnapshot) -> Verdict:
    from google.genai import types

    client = _get_client()
    resp = await client.aio.models.generate_content(
        model=config.GEMINI_MODEL,
        contents=f"Analyse this HTTP request:\n```json\n{_describe(req)}\n```",
        config=types.GenerateContentConfig(
            system_instruction=_SYSTEM_PROMPT,
            response_mime_type="application/json",
            response_schema=_SCHEMA,
            temperature=0.0,
            http_options=types.HttpOptions(timeout=int(config.LLM_TIMEOUT_SECONDS * 1000)),
        ),
    )
    data = json.loads(resp.text)
    return Verdict(
        malicious=bool(data["malicious"]),
        threat_type=str(data.get("threat_type", "other")),
        confidence=float(data.get("confidence", 0.5)),
        reason=str(data.get("reason", "")),
        engine="gemini",
    )


# ---------------------------------------------------------------------------
# Offline heuristic fallback (so tests + demo work without any API key)
# ---------------------------------------------------------------------------
_PRIVILEGED_FIELDS = {
    "is_admin", "isadmin", "admin", "role", "roles", "is_superuser", "is_staff",
    "permissions", "balance", "credit", "verified", "is_verified", "email_verified",
    "account_type", "plan", "tier", "discount", "price",
}
_SUSPICIOUS_DECODED = re.compile(
    r"(<script|union\s+select|\bor\s+1=1|/etc/passwd|\.\./|\$\(|;\s*(rm|cat|wget|curl)\b|eval\(|exec\()",
    re.I,
)
_B64 = re.compile(r"^[A-Za-z0-9+/=]{16,}$")
_HEX = re.compile(r"^(?:\\x[0-9a-f]{2}){4,}$|^(?:[0-9a-f]{2}){8,}$", re.I)
_SSRF = re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\.internal\b|metadata\.google)", re.I)


def _walk(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{path}.{k}" if path else str(k)
            out.append((key, v))
            out.extend(_walk(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_walk(v, f"{path}[{i}]"))
    return out


def _try_decode(s: str) -> str | None:
    if _B64.match(s):
        try:
            dec = base64.b64decode(s + "=" * (-len(s) % 4), validate=False).decode("utf-8", "ignore")
            if dec.isprintable() or "\n" in dec:
                return dec
        except Exception:
            pass
    if _HEX.match(s):
        try:
            return bytes.fromhex(s.replace("\\x", "")).decode("utf-8", "ignore")
        except Exception:
            pass
    if "\\u00" in s:
        try:
            return s.encode().decode("unicode_escape")
        except Exception:
            pass
    return None


def analyze_heuristic(req: RequestSnapshot) -> Verdict:
    body = req.body_json
    auth_user = req.headers.get("x-user-id")
    is_admin_path = "/admin" in req.path
    ev: list[str] = []

    fields = _walk(body) if body is not None else []

    # 1. Mass assignment / privilege escalation on non-admin paths
    if not is_admin_path and req.method in ("POST", "PUT", "PATCH"):
        for k, v in fields:
            leaf = k.split(".")[-1].lower()
            if leaf in _PRIVILEGED_FIELDS:
                ev.append(f"privileged field '{k}'={v!r} on non-admin path")
        if ev:
            return Verdict(True, "mass_assignment", 0.9,
                           "Client attempted to set privileged fields on a user-facing endpoint",
                           "heuristic", ev)

    # 2. BOLA / IDOR: body/query user id conflicts with authenticated user
    if auth_user:
        for k, v in fields:
            leaf = k.split(".")[-1].lower()
            if leaf in ("user_id", "owner_id", "account_id", "from_account") and str(v) != auth_user:
                ev.append(f"{k}={v!r} but X-User-Id={auth_user}")
        m = re.search(r"/users/(\d+)", req.path)
        if m and m.group(1) != auth_user and req.method in ("PUT", "PATCH", "DELETE"):
            ev.append(f"path user id {m.group(1)} != X-User-Id {auth_user}")
        if ev:
            return Verdict(True, "bola_idor", 0.85,
                           "Request references an object belonging to a different user", "heuristic", ev)

    # 3. Encoded / obfuscated payloads
    for k, v in fields + [("query", req.query)]:
        if isinstance(v, str) and len(v) >= 12:
            dec = _try_decode(v)
            if dec and _SUSPICIOUS_DECODED.search(dec):
                ev.append(f"{k} decodes to: {dec[:60]!r}")
    if ev:
        return Verdict(True, "encoded_payload", 0.88, "Encoded payload decodes to an attack string",
                       "heuristic", ev)

    # 4. Business-logic abuse on money endpoints
    if "transfer" in req.path and isinstance(body, dict):
        amt = body.get("amount")
        if isinstance(amt, (int, float)) and (amt <= 0 or amt > 1_000_000):
            return Verdict(True, "business_logic_abuse", 0.8, f"Suspicious transfer amount {amt}",
                           "heuristic", [f"amount={amt}"])
        if body.get("from_account") and body.get("from_account") == body.get("to_account"):
            return Verdict(True, "business_logic_abuse", 0.7, "Transfer to self", "heuristic")

    # 5. SSRF-style URLs
    for k, v in fields:
        if isinstance(v, str) and ("://" in v) and _SSRF.search(v):
            return Verdict(True, "ssrf", 0.85, "URL targets internal/metadata address", "heuristic",
                           [f"{k}={v!r}"])

    return Verdict(False, "none", 0.05, "No contextual anomaly detected", "heuristic")


def mode() -> str:
    if config.GEMINI_API_KEY and not config.FORCE_OFFLINE:
        return f"gemini ({config.GEMINI_MODEL}) with heuristic fallback"
    return "offline heuristic (set GEMINI_API_KEY to enable Gemini)"


async def analyze(req: RequestSnapshot) -> Verdict:
    """Entry point used by the proxy. Prefers Gemini, degrades gracefully to heuristics."""
    if config.GEMINI_API_KEY and not config.FORCE_OFFLINE:
        try:
            return await analyze_with_gemini(req)
        except Exception as exc:  # quota, network, parse errors -> fall back, never fail open silently
            v = analyze_heuristic(req)
            v.reason = f"[gemini error: {type(exc).__name__}: {str(exc)[:80]}] fallback -> {v.reason}"
            return v
    return analyze_heuristic(req)
