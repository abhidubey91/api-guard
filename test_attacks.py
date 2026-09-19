"""Automated attack matrix against a running API-Guardian (:8000) -> mock backend (:8001).

Run as a script:   python test_attacks.py
Run under pytest:  pytest -v test_attacks.py
Both require the backend and proxy to be running (see README / run_all.py).
"""
import base64
import os
import sys
import time

import httpx
import pytest

PROXY = f"http://127.0.0.1:{os.getenv('GUARDIAN_PORT', '8000')}"
HDRS = {"X-User-Id": "1", "Content-Type": "application/json"}

# name, method, path, kwargs, expected_status, expected_engine ("regex" | "ai" | None)
CASES = [
    # ---------- Clean traffic -> 200 ----------
    ("clean: health", "GET", "/api/v1/health", {}, 200, None),
    ("clean: login", "POST", "/api/v1/login",
     {"json": {"username": "alice", "password": "S3cure!pass"}}, 200, None),
    ("clean: list users", "GET", "/api/v1/users", {"params": {"q": "ali"}}, 200, None),
    ("clean: get own user", "GET", "/api/v1/users/1", {}, 200, None),
    ("clean: update own profile", "PUT", "/api/v1/users/1",
     {"json": {"email": "alice.new@example.com", "username": "alice"}}, 200, None),
    ("clean: normal transfer", "POST", "/api/v1/transfer",
     {"json": {"from_account": 1, "to_account": 2, "amount": 25.5}}, 200, None),

    # ---------- Obvious exploits -> 403 by regex ----------
    ("sqli: tautology in login", "POST", "/api/v1/login",
     {"json": {"username": "admin' OR '1'='1", "password": "x"}}, 403, "regex"),
    ("sqli: UNION SELECT in query", "GET", "/api/v1/users",
     {"params": {"q": "x' UNION SELECT username,password FROM users--"}}, 403, "regex"),
    ("sqli: url-encoded tautology", "GET", "/api/v1/users?q=%27%20OR%201%3D1--", {}, 403, "regex"),
    ("sqli: stacked DROP", "POST", "/api/v1/login",
     {"json": {"username": "bob'; DROP TABLE users;--", "password": "x"}}, 403, "regex"),
    ("xss: script tag", "PUT", "/api/v1/users/1",
     {"json": {"username": "<script>alert(1)</script>"}}, 403, "regex"),
    ("xss: img onerror", "PUT", "/api/v1/users/1",
     {"json": {"email": '<img src=x onerror=alert(1)>'}}, 403, "regex"),
    ("xss: javascript: uri", "POST", "/api/v1/profile/avatar",
     {"json": {"url": "javascript:alert(document.cookie)"}}, 403, "regex"),
    ("traversal: ../../etc/passwd", "GET", "/api/v1/users/../../etc/passwd", {}, 403, "regex"),
    ("traversal: encoded", "GET", "/api/v1/users", {"params": {"q": "..%2f..%2f..%2fetc%2fshadow"}},
     403, "regex"),
    ("cmdi: shell chain", "POST", "/api/v1/login",
     {"json": {"username": "bob; cat /etc/passwd", "password": "x"}}, 403, "regex"),
    ("nosqli: $ne operator", "POST", "/api/v1/login",
     {"json": {"username": "admin", "password": {"$ne": ""}}}, 403, "regex"),

    # ---------- Contextual anomalies -> 403 by AI guard (gemini or heuristic) ----------
    ("ai: mass assignment is_admin", "PUT", "/api/v1/users/1",
     {"json": {"username": "dev", "is_admin": True}}, 403, "ai"),
    ("ai: mass assignment role+balance", "POST", "/api/v1/login",
     {"json": {"username": "dev", "password": "x", "role": "superuser", "balance": 999999}}, 403, "ai"),
    ("ai: BOLA transfer from another account", "POST", "/api/v1/transfer",
     {"json": {"from_account": 2, "to_account": 1, "amount": 100}}, 403, "ai"),
    ("ai: IDOR update other user", "PUT", "/api/v1/users/2",
     {"json": {"email": "pwned@evil.com"}}, 403, "ai"),
    ("ai: base64 obfuscated SQLi", "POST", "/api/v1/login",
     {"json": {"username": base64.b64encode(b"' UNION SELECT * FROM users --").decode(),
               "password": "x"}}, 403, "ai"),
    ("ai: hex obfuscated XSS", "PUT", "/api/v1/users/1",
     {"json": {"username": "<script>alert(1)</script>".encode().hex()}}, 403, "ai"),
    ("ai: negative transfer amount", "POST", "/api/v1/transfer",
     {"json": {"from_account": 1, "to_account": 2, "amount": -5000}}, 403, "ai"),
    ("ai: SSRF to cloud metadata", "POST", "/api/v1/profile/avatar",
     {"json": {"url": "http://169.254.169.254/latest/meta-data/iam/"}}, 403, "ai"),
]


_client: httpx.Client | None = None


def _send(method, path, kwargs):
    # One shared client, trust_env=False: avoids per-request Windows proxy lookups (seconds each).
    global _client
    if _client is None:
        _client = httpx.Client(base_url=PROXY, timeout=60, trust_env=False)
    return _client.request(method, path, headers=HDRS, **kwargs)


def _check(name, method, path, kwargs, expected_status, expected_engine):
    t0 = time.perf_counter()
    r = _send(method, path, kwargs)
    ms = (time.perf_counter() - t0) * 1000
    assert r.status_code == expected_status, f"{name}: expected {expected_status}, got {r.status_code}: {r.text[:200]}"
    engine = None
    if r.status_code == 403:
        body = r.json()
        assert body.get("blocked_by") == "API-Guardian", f"{name}: 403 did not come from guardian"
        engine = body["threat"]["engine"]
        if expected_engine == "regex":
            assert engine == "regex", f"{name}: expected regex block, got {engine}"
        elif expected_engine == "ai":
            assert engine in ("gemini", "heuristic"), f"{name}: expected AI block, got {engine}"
    return r, engine, ms


@pytest.fixture(scope="session")
def guardian_up():
    try:
        return _send("GET", "/_guardian/health", {}).json()
    except httpx.ConnectError:
        pytest.skip(f"API-Guardian proxy is not running at {PROXY}")


@pytest.mark.parametrize("name,method,path,kwargs,status,engine", CASES, ids=[c[0] for c in CASES])
def test_case(guardian_up, name, method, path, kwargs, status, engine):
    _check(name, method, path, kwargs, status, engine)


def main() -> int:
    try:
        h = _send("GET", "/_guardian/health", {}).json()
    except httpx.ConnectError:
        print("ERROR: proxy not reachable on :8000. Start backend.py and guardian.proxy first (or run_all.py).")
        return 2
    print(f"Guardian up. LLM mode: {h['llm']}\n")
    passed = failed = 0
    for case in CASES:
        name = case[0]
        try:
            r, engine, ms = _check(*case)
            tag = f"{r.status_code}" + (f" [{engine}]" if engine else "")
            print(f"  PASS  {name:<42} -> {tag:<16} {ms:7.1f} ms")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {name:<42} -> {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(CASES)} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
