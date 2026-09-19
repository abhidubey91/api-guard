"""One-shot demo: start mock backend (:8001) + API-Guardian (:8000), run the attack suite, shut down.

    python run_all.py            # run suite then exit
    python run_all.py --serve    # keep both servers running (Ctrl+C to stop)
"""
import os
import subprocess
import sys
import time

import httpx

PY = sys.executable
GUARDIAN_PORT = os.getenv("GUARDIAN_PORT", "8000")
BACKEND_PORT = os.getenv("BACKEND_PORT", "8001")


def wait_for(url: str, timeout: float = 20.0) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            httpx.get(url, timeout=2.0, trust_env=False)
            return
        except httpx.HTTPError:
            time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for {url}")


def main() -> int:
    serve = "--serve" in sys.argv
    backend = subprocess.Popen([PY, "backend.py"])
    proxy = subprocess.Popen([PY, "-m", "guardian.proxy"])
    try:
        wait_for(f"http://127.0.0.1:{BACKEND_PORT}/api/v1/health")
        wait_for(f"http://127.0.0.1:{GUARDIAN_PORT}/_guardian/health")
        if serve:
            print(f"Servers running. Proxy :{GUARDIAN_PORT} -> backend :{BACKEND_PORT}. Ctrl+C to stop.")
            proxy.wait()
            return 0
        time.sleep(0.5)
        rc = subprocess.call([PY, "test_attacks.py"])
        time.sleep(0.5)
        return rc
    except KeyboardInterrupt:
        return 0
    finally:
        for p in (proxy, backend):
            p.terminate()
        for p in (proxy, backend):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
