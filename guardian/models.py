from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RequestSnapshot:
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body_text: str
    body_json: Optional[Any]
    client_ip: str


@dataclass
class Verdict:
    malicious: bool
    threat_type: str = "none"
    confidence: float = 0.0
    reason: str = ""
    engine: str = "none"          # "regex" | "gemini" | "heuristic"
    evidence: list[str] = field(default_factory=list)
