import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip() 
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GUARDIAN_PORT: int = int(os.getenv("GUARDIAN_PORT", "8000"))
BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8001"))
UPSTREAM_URL: str = os.getenv("UPSTREAM_URL", f"http://127.0.0.1:{BACKEND_PORT}").rstrip("/")
LLM_TIMEOUT_SECONDS: float = float(os.getenv("LLM_TIMEOUT_SECONDS", "15"))
# Set to "1" to force the offline heuristic even if a key is present (useful for tests)
FORCE_OFFLINE: bool = os.getenv("GUARDIAN_OFFLINE", "0") == "1"
