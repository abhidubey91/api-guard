"""API-Guardian reverse proxy: FastAPI app listening on :8000, forwarding safe traffic upstream."""
import json
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import config, dashboard, llm_guard, rules
from .models import RequestSnapshot, Verdict

_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
               "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(base_url=config.UPSTREAM_URL, timeout=20.0, trust_env=False)
    dashboard.banner(config.UPSTREAM_URL, llm_guard.mode(), config.GUARDIAN_PORT)
    try:
        yield
    finally:
        await app.state.client.aclose()
        dashboard.summary()


app = FastAPI(title="API-Guardian", lifespan=lifespan)


async def _snapshot(request: Request) -> tuple[RequestSnapshot, bytes]:
    raw = await request.body()
    text = raw.decode("utf-8", errors="replace")
    body_json = None
    if text.strip():
        try:
            body_json = json.loads(text)
        except ValueError:
            body_json = None
    headers = {k.lower(): v for k, v in request.headers.items()}
    ip = request.client.host if request.client else "unknown"
    ip = headers.get("x-forwarded-for", ip).split(",")[0].strip()
    snap = RequestSnapshot(
        method=request.method,
        path=request.url.path,
        query=request.url.query or "",
        headers=headers,
        body_text=text,
        body_json=body_json,
        client_ip=ip,
    )
    return snap, raw


def _block(snap: RequestSnapshot, verdict: Verdict, started: float) -> JSONResponse:
    latency = (time.perf_counter() - started) * 1000
    dashboard.log_request(snap.client_ip, snap.method, snap.path, verdict, latency)
    return JSONResponse(
        status_code=403,
        content={
            "error": "Forbidden",
            "blocked_by": "API-Guardian",
            "threat": {
                "type": verdict.threat_type,
                "engine": verdict.engine,
                "confidence": round(verdict.confidence, 2),
                "reason": verdict.reason,
                "evidence": verdict.evidence,
            },
            "latency_ms": round(latency, 1),
        },
    )


@app.get("/_guardian/health", include_in_schema=False)
async def health():
    return {"status": "ok", "upstream": config.UPSTREAM_URL, "llm": llm_guard.mode()}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def guard(request: Request, full_path: str):
    started = time.perf_counter()
    snap, raw = await _snapshot(request)

    # 1. Fast local regex pre-check
    verdict = rules.check(snap)
    if verdict.malicious:
        return _block(snap, verdict, started)

    # 2. AI / contextual anomaly analysis
    verdict = await llm_guard.analyze(snap)
    if verdict.malicious:
        return _block(snap, verdict, started)

    # 3. Forward upstream
    client: httpx.AsyncClient = request.app.state.client
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    fwd_headers["x-forwarded-for"] = snap.client_ip
    fwd_headers["x-guardian-verdict"] = f"safe;engine={verdict.engine};conf={verdict.confidence:.2f}"
    try:
        upstream = await client.request(
            snap.method, "/" + full_path,
            params=request.query_params, headers=fwd_headers, content=raw,
        )
    except httpx.HTTPError as exc:
        latency = (time.perf_counter() - started) * 1000
        dashboard.log_request(snap.client_ip, snap.method, snap.path, verdict, latency, upstream_status=502)
        return JSONResponse(status_code=502, content={"error": "Bad Gateway", "detail": str(exc)})

    latency = (time.perf_counter() - started) * 1000
    dashboard.log_request(snap.client_ip, snap.method, snap.path, verdict, latency, upstream.status_code)
    resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in _HOP_BY_HOP}
    return Response(content=upstream.content, status_code=upstream.status_code, headers=resp_headers)


def main():
    import uvicorn
    uvicorn.run("guardian.proxy:app", host="127.0.0.1", port=config.GUARDIAN_PORT, log_level="warning")


if __name__ == "__main__":
    main()
