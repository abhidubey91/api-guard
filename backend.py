"""Mock upstream target API on :8001 (the thing API-Guardian protects)."""
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Mock Target Backend")

_USERS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": False, "balance": 500},
    2: {"id": 2, "username": "bob", "email": "bob@example.com", "is_admin": False, "balance": 120},
}


class Login(BaseModel):
    username: str
    password: str


class Transfer(BaseModel):
    from_account: int
    to_account: int
    amount: float


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "mock-backend"}


@app.post("/api/v1/login")
def login(body: Login):
    return {"token": f"tok-{body.username}", "user": body.username}


@app.get("/api/v1/users")
def list_users(q: str | None = None):
    users = list(_USERS.values())
    if q:
        users = [u for u in users if q.lower() in u["username"]]
    return {"users": users}


@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int):
    if user_id not in _USERS:
        raise HTTPException(404, "user not found")
    return _USERS[user_id]


@app.put("/api/v1/users/{user_id}")
def update_user(user_id: int, body: dict[str, Any]):
    # Deliberately naive: the backend trusts whatever it receives (mass-assignment prone).
    if user_id not in _USERS:
        raise HTTPException(404, "user not found")
    _USERS[user_id].update(body)
    return _USERS[user_id]


@app.post("/api/v1/transfer")
def transfer(body: Transfer):
    return {"status": "queued", "from": body.from_account, "to": body.to_account, "amount": body.amount}


@app.post("/api/v1/profile/avatar")
def avatar(body: dict[str, Any]):
    return {"status": "ok", "fetched_from": body.get("url")}


if __name__ == "__main__":
    import os
    import uvicorn
    uvicorn.run("backend:app", host="127.0.0.1", port=int(os.getenv("BACKEND_PORT", "8001")), log_level="warning")
