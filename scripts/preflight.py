"""Presentation preflight: run this before a demo to confirm the installation is healthy.

Usage (from the project folder, with the virtual environment created by run.ps1 / run.sh):

    .venv/Scripts/python.exe scripts/preflight.py        # Windows
    .venv/bin/python scripts/preflight.py                # Linux / macOS / WSL

It never touches the network and never launches a scanner. It checks the Python version and
dependencies, the configuration file, which tools are installed, whether the port is free, and then
boots the application in-process to exercise health, planning (rules engine), a simulated run and a
report download. The exit code is 0 when everything passed.
"""
from __future__ import annotations

import importlib
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CHECK, CROSS, WARN = "[PASS]", "[FAIL]", "[WARN]"
results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    print(f"{status} {name}" + (f"  - {detail}" if detail else ""))


def check_python() -> None:
    if sys.version_info >= (3, 10):  # noqa: UP036 - must keep working on old interpreters to report them
        record(CHECK, "Python version", f"{sys.version.split()[0]}")
    else:
        record(CROSS, "Python version", f"{sys.version.split()[0]} found, 3.10 or newer required")


def check_dependencies() -> None:
    missing = []
    for module in ("fastapi", "uvicorn", "pydantic", "dotenv", "httpx"):
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    if missing:
        record(CROSS, "Dependencies", f"missing: {', '.join(missing)} (run: pip install -r requirements.txt)")
    else:
        record(CHECK, "Dependencies", "fastapi, uvicorn, pydantic, python-dotenv, httpx importable")
    try:
        importlib.import_module("anthropic")
        record(CHECK, "Anthropic SDK", "installed")
    except ImportError:
        record(WARN, "Anthropic SDK", "not installed; the planner will use OpenAI-compatible or rules mode")


def check_env_file() -> None:
    env = ROOT / ".env"
    if not env.exists():
        record(WARN, "Configuration (.env)", "missing; run.ps1 / run.sh create it from .env.example on first start")
        return
    from dotenv import dotenv_values
    values = {k: v for k, v in dotenv_values(env).items() if v}
    provider = values.get("HYBRIDSEC_AI_PROVIDER", "auto")
    has_key = bool(values.get("ANTHROPIC_API_KEY") or values.get("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
                   or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN"))
    if has_key:
        credentials = "API key or token configured"
    elif _anthropic_login_profile():
        credentials = "Anthropic login profile found"
    else:
        credentials = "no API key, token or login profile found"
        if provider == "auto":
            credentials += " (rules planner will answer)"
    detail = f"provider={provider}, {credentials}"
    record(CHECK, "Configuration (.env)", detail)
    if values.get("HYBRIDSEC_ALLOWED_TARGETS"):
        record(CHECK, "Target allow-list", values["HYBRIDSEC_ALLOWED_TARGETS"])
    else:
        record(WARN, "Target allow-list", "empty: any target the operator confirms as authorized is accepted")


def _anthropic_login_profile() -> bool:
    """True when the Anthropic SDK finds an `ant auth login` profile, the same question app/config.py asks.
    Asked here directly: importing app.config this early would fix its data directory before
    check_application() points it at a throwaway folder."""
    try:
        from anthropic.lib.credentials._constants import (
            _has_active_profile_config,
            _has_auto_discoverable_credentials,
        )
        return bool(_has_auto_discoverable_credentials() or _has_active_profile_config())
    except Exception:  # no SDK, or an unreadable profile folder: the SDK could not use a profile either
        return False


def check_tools() -> None:
    from app.tools.registry import list_tools
    for tool in list_tools():
        if tool.installed:
            record(CHECK, f"Tool: {tool.display_name}", f"{tool.path} (version {tool.version or 'unknown'})")
        else:
            record(WARN, f"Tool: {tool.display_name}", "not installed; live runs need it, simulation works without it")


def configured_bind() -> tuple[str, int]:
    """The address run.sh / run.ps1 would bind: the shell environment first, then .env, then the defaults."""
    values: dict[str, str] = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        from dotenv import dotenv_values
        values = {k: v for k, v in dotenv_values(env_file).items() if v}
    host = os.getenv("HYBRIDSEC_HOST") or values.get("HYBRIDSEC_HOST") or "127.0.0.1"
    port = os.getenv("HYBRIDSEC_PORT") or values.get("HYBRIDSEC_PORT") or "8000"
    try:
        return host, int(port)
    except ValueError:
        record(WARN, "HYBRIDSEC_PORT", f"{port!r} is not a number; the launch scripts will fail (checking port 8000)")
        return host, 8000


# Nothing can connect to a wildcard bind address (Windows answers 0.0.0.0 with "address not available"), so the
# port check and the closing URL use the matching loopback address instead; uvicorn binds "::" IPv6-only.
WILDCARD_LOOPBACK = {"0.0.0.0": "127.0.0.1", "::": "::1"}


def check_port(host: str = "127.0.0.1", port: int = 8000) -> None:
    probe = WILDCARD_LOOPBACK.get(host, host)
    family = socket.AF_INET6 if ":" in probe else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            busy = sock.connect_ex((probe, port)) == 0
    except OSError as exc:  # connect_ex still raises when the name does not resolve
        record(WARN, f"Port {port}", f"could not check {host}:{port} ({exc})")
        return
    if busy:
        record(WARN, f"Port {port}", "something is already listening (is HybridSec already running? then that is fine)")
    else:
        record(CHECK, f"Port {port}", "free")


def check_application() -> None:
    # Isolate the smoke test from the real database and .env so a demo machine is left untouched.
    tmp = tempfile.mkdtemp(prefix="hybridsec-preflight-")
    os.environ["HYBRIDSEC_DATA_DIR"] = tmp
    os.environ["HYBRIDSEC_ENV_FILE"] = ""
    os.environ["HYBRIDSEC_AI_PROVIDER"] = "rules"
    try:
        import logging

        from fastapi.testclient import TestClient

        from app.main import app
        # Keep the checklist readable: the app and the HTTP client log every request at INFO.
        for name in ("hybridsec", "hybridsec.pipeline", "hybridsec.planner", "httpx", "httpx2", "uvicorn"):
            logging.getLogger(name).setLevel(logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    except Exception as exc:
        record(CROSS, "Application import", f"{type(exc).__name__}: {exc}")
        return
    try:
        with TestClient(app, base_url="http://localhost") as client:
            health = client.get("/api/health")
            record(CHECK if health.status_code == 200 else CROSS, "GET /api/health", f"HTTP {health.status_code}")
            plan = client.post("/api/ai/plan", json={
                "tools": ["nmap", "whatweb"],
                "objective": "Preflight: plan a hybrid port scan and web fingerprint of an authorized lab host."})
            ok = plan.status_code == 200 and plan.json()["provider"] == "rules"
            record(CHECK if ok else CROSS, "POST /api/ai/plan (rules engine)", f"HTTP {plan.status_code}")
            run = client.post("/api/hybridizations/execute", json={
                "target": "127.0.0.1", "authorized": True, "simulate": True, "label": "preflight"})
            if run.status_code != 202:
                record(CROSS, "Simulated run", f"HTTP {run.status_code}: {run.text[:120]}")
                return
            run_id = run.json()["id"]
            deadline = time.time() + 30
            status = "queued"
            while time.time() < deadline and status in {"queued", "running"}:
                status = client.get(f"/api/runs/{run_id}").json()["status"]
                time.sleep(0.2)
            record(CHECK if status == "completed" else CROSS, "Simulated run", f"finished with status {status}")
            report = client.get(f"/api/runs/{run_id}/report", params={"format": "html"})
            record(CHECK if report.status_code == 200 and "<!doctype html>" in report.text else CROSS,
                   "Report download (HTML)", f"HTTP {report.status_code}")
            page = client.get("/")
            record(CHECK if page.status_code == 200 and "app.js" in page.text else CROSS,
                   "Dashboard page", f"HTTP {page.status_code}")
    except Exception as exc:
        record(CROSS, "Application smoke test", f"{type(exc).__name__}: {exc}")


def main() -> int:
    print("HybridSec presentation preflight\n" + "=" * 34)
    check_python()
    check_dependencies()
    check_env_file()
    check_tools()
    host, port = configured_bind()
    check_port(host, port)
    check_application()
    failed = [r for r in results if r[0] == CROSS]
    warned = [r for r in results if r[0] == WARN]
    print("=" * 34)
    print(f"{len(results) - len(failed) - len(warned)} passed, {len(warned)} warnings, {len(failed)} failed")
    if failed:
        print("Fix the failures above before presenting.")
        return 1
    url_host = WILDCARD_LOOPBACK.get(host, host)
    if ":" in url_host:
        url_host = f"[{url_host}]"
    print(f"Ready to present. Start the server with run.ps1 or run.sh and open http://{url_host}:{port}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
