# API-Guardian (POC)

An LLM-assisted API firewall / reverse proxy. Sits in front of a backend API, inspects each
request with a fast regex pre-check and then an AI contextual guard, and either blocks it
(HTTP 403 with a threat report) or forwards it upstream with `httpx`.

```
Client -> API-Guardian :8000 -> [regex] -> [Gemini 2.5 Flash / heuristic] -> upstream :8001
```

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env          # optional: add GEMINI_API_KEY for the real LLM guard
python run_all.py             # starts backend + proxy, fires the attack suite, exits
```

Or run the pieces yourself in three terminals:

```bash
python backend.py             # mock target API on :8001
python -m guardian.proxy      # API-Guardian on :8000 (rich dashboard prints here)
python test_attacks.py        # attack matrix (or: pytest -v test_attacks.py)
```

## LLM guard: Gemini (free tier) with offline fallback

* With `GEMINI_API_KEY` set (free key from https://aistudio.google.com/app/apikey), requests that
  pass the regex stage are sent to `gemini-2.5-flash` using `google-genai` with
  `response_mime_type="application/json"` and a strict `response_schema`, so the verdict is
  always machine-readable: `{malicious, threat_type, confidence, reason}`.
* Without a key (or if Gemini errors / hits quota), the guard degrades to a local heuristic
  analyser that catches the same classes of contextual anomaly: mass assignment
  (`is_admin`, `role`, `balance`...), BOLA/IDOR (body or path user id != `X-User-Id`),
  base64/hex/unicode-obfuscated attack strings, business-logic abuse on `/transfer`, and SSRF
  to internal/metadata addresses. This keeps the POC and test-suite fully runnable offline.
* Set `GUARDIAN_OFFLINE=1` to force the heuristic even when a key is present.
* If 8000/8001 are busy, set `GUARDIAN_PORT` / `BACKEND_PORT` (env or `.env`); every script honours them.

## Layout

| File | Purpose |
|---|---|
| `guardian/proxy.py` | FastAPI reverse proxy, blocking/forwarding, 403 threat payload |
| `guardian/rules.py` | Regex pre-check: SQLi, XSS, path traversal, command & NoSQL injection (URL-decoded) |
| `guardian/llm_guard.py` | Gemini structured-output analysis + heuristic fallback |
| `guardian/dashboard.py` | `rich` colour-coded live log: time, IP, endpoint, verdict, engine, confidence, latency |
| `backend.py` | Mock upstream API (`/api/v1/login`, `/users`, `/transfer`, ...) |
| `test_attacks.py` | Attack matrix: clean (200), obvious exploits (403 regex), contextual anomalies (403 AI) |
| `run_all.py` | Starts everything, runs the suite, tears down |

## Blocked response shape

```json
{
  "error": "Forbidden",
  "blocked_by": "API-Guardian",
  "threat": {
    "type": "mass_assignment",
    "engine": "gemini",
    "confidence": 0.92,
    "reason": "Client attempted to set is_admin on a user profile endpoint",
    "evidence": []
  },
  "latency_ms": 640.2
}
```
