"""Fast local regex pre-check. Cheap, runs before any LLM call."""
import re
from urllib.parse import unquote_plus

from .models import RequestSnapshot, Verdict

# (threat_type, compiled pattern, human label)
_RULES: list[tuple[str, re.Pattern, str]] = [
    # --- SQL injection ---
    ("sqli", re.compile(r"\bunion\b[\s/*]+(all[\s/*]+)?\bselect\b", re.I), "UNION SELECT"),
    ("sqli", re.compile(r"(['\"`])\s*(or|and)\s*\1?\s*\d+\s*=\s*\d+", re.I), "tautology ' OR 1=1"),
    ("sqli", re.compile(r"(['\"])\s*(or|and)\s*\1\s*\w+\s*\1\s*=\s*\1", re.I), "tautology ' OR 'x'='x"),
    ("sqli", re.compile(r"\b(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I), "OR 1=1 (unquoted)"),
    ("sqli", re.compile(r";\s*(drop|delete|insert|update|alter|truncate|exec)\b", re.I), "stacked query"),
    ("sqli", re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.I), "time-based SQLi"),
    ("sqli", re.compile(r"(--|#|/\*)\s*$", re.M), "SQL comment terminator"),
    ("sqli", re.compile(r"\b(information_schema|sysobjects|xp_cmdshell)\b", re.I), "schema probing"),
    # --- XSS ---
    ("xss", re.compile(r"<\s*script\b", re.I), "<script> tag"),
    ("xss", re.compile(r"javascript\s*:", re.I), "javascript: URI"),
    ("xss", re.compile(r"\bon(error|load|click|mouseover|focus|submit)\s*=", re.I), "inline event handler"),
    ("xss", re.compile(r"<\s*(iframe|img|svg|object|embed)\b[^>]*\b(src|onerror|onload)\s*=", re.I), "HTML injection vector"),
    # --- Path traversal ---
    ("path_traversal", re.compile(r"(\.\./|\.\.\\){1,}"), "../ traversal"),
    ("path_traversal", re.compile(r"(%2e%2e[%2f\\/]|\.%2e/|%2e\./)", re.I), "encoded traversal"),
    ("path_traversal", re.compile(r"(/etc/(passwd|shadow)|c:\\windows\\|boot\.ini)", re.I), "sensitive file path"),
    # --- Command injection ---
    ("cmd_injection", re.compile(r"(;|\||&&|\$\(|`)\s*(cat|ls|rm|wget|curl|nc|bash|sh|powershell|whoami|id)\b", re.I), "shell command chain"),
    # --- NoSQL injection ---
    ("nosqli", re.compile(r"\$(where|ne|gt|lt|regex|exists)\b", re.I), "Mongo operator injection"),
]


def _decode_layers(value: str, max_layers: int = 3) -> str:
    """Peel a few layers of URL-encoding so %27%20OR... is still caught."""
    out = value
    for _ in range(max_layers):
        dec = unquote_plus(out)
        if dec == out:
            break
        out = dec
    return out


def _surfaces(req: RequestSnapshot) -> list[tuple[str, str]]:
    surfaces = [("path", req.path), ("query", req.query), ("body", req.body_text)]
    for h in ("user-agent", "referer", "x-forwarded-for", "cookie"):
        if h in req.headers:
            surfaces.append((f"header:{h}", req.headers[h]))
    return surfaces


def check(req: RequestSnapshot) -> Verdict:
    for surface, raw in _surfaces(req):
        if not raw:
            continue
        for candidate in {raw, _decode_layers(raw)}:
            for threat, pattern, label in _RULES:
                m = pattern.search(candidate)
                if m:
                    return Verdict(
                        malicious=True,
                        threat_type=threat,
                        confidence=0.97,
                        reason=f"Regex rule matched: {label}",
                        engine="regex",
                        evidence=[f"{surface}: ...{candidate[max(0, m.start()-20):m.end()+20]}..."],
                    )
    return Verdict(malicious=False, engine="regex", confidence=0.0, reason="no regex match")
