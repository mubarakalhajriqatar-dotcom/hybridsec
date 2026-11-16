"""Tests for the HybridSec API and its building blocks. They run fully offline: runs use simulation mode,
scanner calls are replaced with monkeypatch, and no real scanner is ever started.

The environment is isolated before the app is imported: settings come from a throwaway .env file and the
database lives in a temporary directory, so a developer's real .env, API keys and run history are never
read or modified.
"""
from __future__ import annotations

import inspect
import os
import shutil
import socket
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="hybridsec-test-")
for _name in list(os.environ):
    if _name.startswith(("HYBRIDSEC_", "ANTHROPIC_", "OPENAI_")):
        del os.environ[_name]  # the developer's own settings and keys must not leak into the tests
os.environ["HYBRIDSEC_ENV_FILE"] = os.path.join(_TMP, "test.env")
os.environ["HYBRIDSEC_DATA_DIR"] = _TMP
os.environ["HYBRIDSEC_AI_PROVIDER"] = "rules"
os.environ["HYBRIDSEC_ALLOWED_TARGETS"] = ""
# Custom tools may use a program that is never installed, so registering one never depends on this machine.
os.environ["HYBRIDSEC_CUSTOM_PROGRAMS"] = "hybridsec-test-missing-program,curl,whois,sslscan"

# The application is imported only now, so that it reads the isolated environment set up above.
import pytest
from dotenv import dotenv_values
from fastapi.testclient import TestClient

from app import hybrid, storage
from app import main as app_main
from app.compare import compare_runs
from app.config import ENV_FILE, settings
from app.envfile import EnvValueError, update_env_file
from app.main import app
from app.reports import render_csv, render_markdown
from app.routers.settings_api import peer_is_local, require_local
from app.schemas import (
    CustomToolCreate,
    ExecuteRequest,
    PortFinding,
    Run,
    RunSummary,
    StageResult,
    VulnFinding,
    WebFinding,
)
from app.security import TargetError, matches_allowlist_entry, normalize_target, validate_allowlist_entry
from app.tools import custom, parsers
from app.tools.runner import CommandResult

# --- Fixtures and helpers -------------------------------------------------------------------------

def allow_testclient_as_local() -> None:
    """Let the test client use the settings endpoints.

    Its peer address is the literal string "testclient", not a loopback IP, so require_local would
    (correctly) answer 403, and the execute endpoint would refuse custom tools (peer_is_local).
    """
    app.dependency_overrides[require_local] = lambda: None
    app.dependency_overrides[peer_is_local] = lambda: True


@pytest.fixture(scope="module")
def client():
    """One API client for the whole module. Starting it runs the app's startup, which creates the database
    tables. "localhost" is a Host header the server trusts."""
    allow_testclient_as_local()
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def start_run(client: TestClient, **fields):
    """POST /api/hybridizations/execute: an authorized, simulated run on 127.0.0.1 unless `fields` override it."""
    body = {"target": "127.0.0.1", "authorized": True, "simulate": True}
    body.update(fields)
    return client.post("/api/hybridizations/execute", json=body)


def wait_for_run(client: TestClient, run_id: str, timeout: float = 20) -> dict:
    """Poll a run until it has finished, then return it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "failed"}:
            return run
        time.sleep(0.1)
    raise AssertionError("run did not finish in time")


# A custom tool for the tests: its program is on the test allow-list and never installed, and it runs once per web URL.
CUSTOM_BODY = {"name": "pytestcheck", "program": "hybridsec-test-missing-program", "args": ["--quiet", "{url}"],
               "scope": "url", "timeout_seconds": 30}


def new_plan(client: TestClient, tools: list[str], objective: str) -> dict:
    """Create and save a plan through the API (the rules planner answers) and return it."""
    return client.post("/api/ai/plan", json={"tools": tools, "objective": objective}).json()


def make_run(**fields) -> Run:
    """A Run model for unit tests. Every field can be overridden."""
    values = {"id": "test00000001", "target": "127.0.0.1", "status": "completed", "tools": ["nmap"],
              "created_at": datetime.now(timezone.utc)}
    values.update(fields)
    return Run(**values)


def fake_scanner(monkeypatch, *, stdout: str = "", stderr: str = "", exit_code: int = 0) -> None:
    """Pretend every scanner is installed and make each call return the given output. Nothing is executed, and
    name lookups answer IPv4 only, so a host-name target never reaches the real resolver."""
    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "find_program", lambda program: (f"/fake/bin/{program}", None))  # custom tools
    monkeypatch.setattr(hybrid, "run_command", lambda command, timeout, max_chars=None: CommandResult(
        command=command, exit_code=exit_code, stdout=stdout, stderr=stderr, duration_seconds=0.1))
    monkeypatch.setattr(hybrid, "_address_families", lambda hostname: {socket.AF_INET})


def run_stage_handler(handler, run: Run, context: dict | None = None, stage_index: int = 0) -> StageResult:
    """Call one pipeline stage handler directly, with a 30-second stage budget, and return its stage."""
    stage = run.stages[stage_index]
    handler(hybrid.manager, run, ExecuteRequest(target=run.target, authorized=True), stage,
            {} if context is None else context, 30.0)
    return stage


# --- Target validation and scope ------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("127.0.0.1", "127.0.0.1"),
    (" Example.COM ", "example.com"),
    ("10.0.0.0/24", "10.0.0.0/24"),
    ("::1", "::1"),
])
def test_normalize_target_accepts_valid(raw, expected):
    """A single IP address, hostname or small CIDR is accepted and returned in canonical form."""
    assert normalize_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "-sS 127.0.0.1", "http://example.com", "10.0.0.0/8", "a;b", "host name",
                                 "$(whoami)", "../etc",
                                 # nmap range / list / wildcard syntax and IPv6 zone ids must never pass
                                 "0-255.0-255.0-255.0-255", "10.0-255.0-255.1", "1-254", "10.0.0.*",
                                 "10.0.0.1,10.0.0.2", "fe80::1%eth0", "123.456", "example.123"])
def test_normalize_target_rejects_bad(raw):
    """Shell syntax, URLs, paths, oversized CIDRs and nmap range or list syntax never reach a scanner."""
    with pytest.raises(TargetError):
        normalize_target(raw)


def test_allowlist_wildcards_never_match_ip_addresses():
    """*.domain allow-list entries match subdomains only, never IP addresses; CIDR entries match by containment."""
    assert matches_allowlist_entry("web.lab.local", "*.lab.local")
    assert not matches_allowlist_entry("lab.local", "*.lab.local")
    assert not matches_allowlist_entry("10.1.2.3", "*.1.2.3")
    assert matches_allowlist_entry("10.1.2.3", "10.1.0.0/16")
    assert not matches_allowlist_entry("10.2.2.3", "10.1.0.0/16")
    with pytest.raises(TargetError):
        validate_allowlist_entry("*.1.2.3")
    assert validate_allowlist_entry("10.0.0.0/8") == "10.0.0.0/8"


# --- Request guards -------------------------------------------------------------------------------

def test_host_header_and_cross_site_guards(client):
    """A foreign Host header gets 400 and a cross-site browser write gets 403; same-origin requests pass."""
    body = {"tools": ["nmap"], "objective": "Guard test: plan a port scan of an authorized lab host."}
    assert client.get("/api/tools", headers={"Host": "evil.example"}).status_code == 400
    assert client.post("/api/ai/plan", json=body, headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.post("/api/ai/plan", json=body, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    ok = client.post("/api/ai/plan", json=body,
                     headers={"Host": "localhost:8000", "Origin": "http://localhost:8000",
                                  "Sec-Fetch-Site": "same-origin"})
    assert ok.status_code == 200


def test_settings_rejects_non_loopback_peer():
    """The settings endpoints refuse every client that is not on the machine running HybridSec, and so do the
    custom-tool endpoints and a run that names a custom tool (its arguments must never leave the machine)."""
    app.dependency_overrides.clear()
    try:
        with TestClient(app, base_url="http://localhost") as remote_client:
            assert remote_client.get("/api/settings").status_code == 403
            assert remote_client.put("/api/settings", json={"ai_provider": "rules"}).status_code == 403
            tool = custom.validate_definition(CustomToolCreate(**CUSTOM_BODY),
                                              custom.allowed_programs(settings.custom_programs), datetime.now(timezone.utc))
            assert storage.add_custom_tool(tool, custom.MAX_CUSTOM_TOOLS) == "added"
            assert remote_client.get("/api/tools/custom").status_code == 403
            assert remote_client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name="pytestother")).status_code == 403
            assert remote_client.delete("/api/tools/custom/pytestcheck").status_code == 403
            denied = start_run(remote_client, tools=["nmap", "pytestcheck"])
            assert denied.status_code == 403 and "only be run from the machine running HybridSec" in denied.json()["detail"]
            legacy = remote_client.post("/hybridizations/execute", json={"target": "127.0.0.1", "authorized": True,
                                                                         "simulate": True, "tools": ["nmap", "pytestcheck"]})
            assert legacy.status_code == 403 and "only be run from the machine running HybridSec" in legacy.json()["detail"]
            # An unknown name is answered with the built-in tools only: the error must not list the custom tools to
            # another machine either (the local peer sees them, see test_execute_with_plan_cannot_add_tools).
            for path in ("/api/hybridizations/execute", "/hybridizations/execute"):
                unknown = remote_client.post(path, json={"target": "127.0.0.1", "authorized": True, "simulate": True,
                                                         "tools": ["masscan"]})
                assert unknown.status_code == 400 and unknown.json()["detail"] == \
                    "Unknown tool(s): masscan. Supported: nmap, whatweb, nikto.", path
    finally:
        storage.delete_custom_tool("pytestcheck")
        allow_testclient_as_local()


def test_execute_requires_authorization(client):
    """A run is refused unless the operator confirms they may test the target."""
    resp = start_run(client, authorized=False)
    assert resp.status_code == 400
    assert "authorized" in resp.json()["detail"]


# --- System endpoints and dashboard ---------------------------------------------------------------

def test_health_and_tools(client):
    """Health reports the planner and consistent limits; /api/tools lists the three supported tools."""
    health = client.get("/api/health").json()
    assert health["status"] == "ok" and health["ai_provider"] == "rules"
    assert set(health["limits"]) == {"max_timeout_seconds", "default_timeout_seconds", "max_top_ports",
                                     "max_concurrent_runs"}
    assert health["limits"]["default_timeout_seconds"] <= health["limits"]["max_timeout_seconds"]
    tools = client.get("/api/tools").json()
    assert {t["name"] for t in tools} == {"nmap", "whatweb", "nikto"}


def test_dashboard_served(client):
    """The dashboard page is served at /."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


# --- Planner --------------------------------------------------------------------------------------

def test_plan_rules_engine(client):
    """Without an API key the rules planner answers: tools in stage order, authorization required, plan saved."""
    resp = client.post("/api/ai/plan", json={
        "tools": ["whatweb", "nmap"],
        "objective": "Create a hybrid cybersecurity tool that uses Nmap to discover open ports and WhatWeb "
                     "to identify technologies running on discovered web services.",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "planned" and body["provider"] == "rules"
    assert [s["tool"] for s in body["plan"]["workflow"]] == ["nmap", "whatweb"]
    assert body["plan"]["safety_controls"]["authorization_required"] is True
    assert client.get(f"/api/ai/plans/{body['id']}").status_code == 200
    assert any(p["id"] == body["id"] for p in client.get("/api/ai/plans").json())


def test_legacy_plan_alias(client):
    """The original project's POST /ai/plan path still works."""
    resp = client.post("/ai/plan", json={"tools": ["nmap"], "objective": "Scan ports on an authorized lab host."})
    assert resp.status_code == 200


def test_plan_rejects_unknown_tool(client):
    """Planning with an unsupported tool is refused with 400."""
    resp = client.post("/api/ai/plan", json={"tools": ["metasploit"], "objective": "Do something with this tool."})
    assert resp.status_code == 400


def test_refine_plan_without_provider_keeps_plan_and_explains(client):
    """Without an AI provider, refining creates a linked revision that keeps the plan and explains why."""
    client.put("/api/settings", json={"ai_provider": "rules"})
    parent = new_plan(client, ["nmap", "whatweb"], "Hybrid port scan plus web fingerprint workflow.")
    resp = client.post(f"/api/ai/plans/{parent['id']}/refine", json={"feedback": "Make the summary shorter."})
    assert resp.status_code == 200, resp.text
    child = resp.json()
    assert child["parent_id"] == parent["id"] and child["revision"] == 2
    assert child["feedback"] == "Make the summary shorter."
    assert child["plan"] == parent["plan"]
    assert "Refinement needs an AI provider" in child["note"]
    assert client.get(f"/api/ai/plans/{child['id']}").status_code == 200
    assert client.post("/api/ai/plans/doesnotexist/refine", json={"feedback": "anything"}).status_code == 404
    assert client.post(f"/api/ai/plans/{parent['id']}/refine", json={"feedback": "x"}).status_code == 422


# --- Runs in simulation mode ----------------------------------------------------------------------

def test_simulated_run_end_to_end(client):
    """A simulated three-tool run from a plan completes, fills every section and downloads in every format."""
    plan = new_plan(client, ["nmap", "whatweb", "nikto"], "Hybrid port, fingerprint and vuln check workflow.")
    resp = start_run(client, timeout_seconds=60, top_ports=100, plan_id=plan["id"], label="pytest")
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "queued" and resp.json()["started_at"] is None  # the queued run, not the live one
    run = wait_for_run(client, resp.json()["id"])
    assert run["status"] == "completed" and run["mode"] == "simulated"
    assert run["tools"] == ["nmap", "whatweb", "nikto"]
    assert all(s["status"] == "simulated" for s in run["stages"])
    assert run["summary"]["open_ports"] == len(run["ports"]) > 0
    assert run["summary"]["web_services"] == len(run["web"]) > 0
    assert run["summary"]["vulnerabilities"] == len(run["vulns"]) > 0
    assert 0 <= run["summary"]["risk_score"] <= 100
    assert run["log"]

    for fmt, needle in [("json", '"target"'), ("csv", "section,host,port"), ("md", "# HybridSec"),
                        ("html", "<!doctype html>")]:
        report = client.get(f"/api/runs/{run['id']}/report", params={"format": fmt})
        assert report.status_code == 200
        assert needle in report.text
        assert "attachment" in report.headers["content-disposition"]

    items = client.get("/api/runs").json()
    assert items[0]["id"] == run["id"] and items[0]["label"] == "pytest"


def test_compare_two_runs(client):
    """Two finished runs can be compared."""
    ids = [wait_for_run(client, start_run(client, target=target).json()["id"])["id"]
           for target in ("127.0.0.1", "10.10.10.10")]
    diff = client.get("/api/compare", params={"base": ids[0], "other": ids[1]}).json()
    assert diff["base"]["id"] == ids[0] and diff["other"]["id"] == ids[1]
    assert isinstance(diff["ports_added"], list) and isinstance(diff["risk_delta"], int)
    # Only a completed run is scored, so against a failed run the delta is null, whatever score its summary holds.
    storage.save_run(make_run(id="cmpfail00001", status="failed", error="nmap: boom",
                              summary=RunSummary(risk_score=40)))
    try:
        diff = client.get("/api/compare", params={"base": ids[0], "other": "cmpfail00001"}).json()
        assert diff["risk_delta"] is None and diff["note"].startswith("The other run failed")
    finally:
        storage.delete_run("cmpfail00001")


def test_delete_run(client):
    """A finished run can be deleted and is gone afterwards."""
    run = wait_for_run(client, start_run(client).json()["id"])
    assert client.delete(f"/api/runs/{run['id']}").status_code == 204
    assert client.get(f"/api/runs/{run['id']}").status_code == 404


def test_execute_with_plan_cannot_add_tools(client):
    """A run started from a plan may leave planned tools out but never add new ones."""
    plan = new_plan(client, ["nmap", "whatweb"], "Port scan then fingerprint for an authorized lab host.")
    denied = start_run(client, plan_id=plan["id"], tools=["nmap", "whatweb", "nikto"])
    assert denied.status_code == 400 and "nikto" in denied.json()["detail"]
    # Dropping a planned tool is allowed and recorded on the run.
    ok = start_run(client, plan_id=plan["id"], tools=["nmap"])
    assert ok.status_code == 202
    run = wait_for_run(client, ok.json()["id"])
    assert run["tools"] == ["nmap"] and run["plan_id"] == plan["id"]
    # Without an explicit list the plan's workflow is used.
    ok = start_run(client, plan_id=plan["id"])
    assert wait_for_run(client, ok.json()["id"])["tools"] == ["nmap", "whatweb"]
    # Plans never contain custom tools, so one cannot be added to a plan run. Without a plan a custom tool runs
    # after at least one built-in tool, from the run's own copy of its definition; its output is kept, not scored.
    assert client.post("/api/tools/custom", json=CUSTOM_BODY).status_code == 201
    try:
        denied = start_run(client, plan_id=plan["id"], tools=["nmap", "pytestcheck"])
        assert denied.status_code == 400 and "pytestcheck" in denied.json()["detail"]
        alone = start_run(client, tools=["pytestcheck"])
        assert alone.status_code == 400 and "Choose at least one of nmap, whatweb or nikto" in alone.json()["detail"]
        ok = start_run(client, tools=["pytestcheck", "nmap"])
        assert ok.status_code == 202, ok.text
        run = wait_for_run(client, ok.json()["id"])
        assert run["tools"] == ["nmap", "pytestcheck"] and "pytestcheck" not in run["profiles"]
        assert (run["stages"][1]["stage"], run["stages"][1]["tool"], run["stages"][1]["status"]) == \
            ("custom_tool", "pytestcheck", "simulated")
        assert run["custom_tools"]["pytestcheck"]["args"] == ["--quiet", "{url}"]
        assert run["custom_outputs"] and all(o["target"].startswith("http") for o in run["custom_outputs"])
        # A simulated call was never started, so it has no exit code, and the reports say so instead of "exit code 0".
        assert all((o["ended"], o["exit_code"]) == ("simulated", None) for o in run["custom_outputs"])
        report = client.get(f"/api/runs/{run['id']}/report", params={"format": "md"}).text
        assert "|  simulated, not started  |" in report and "exit code" not in report
        assert run["summary"]["partial"] is False
        # A definition that no longer passes the rules (the allow-list was shortened) is refused, simulated or not,
        # and the listing says why.
        try:
            with pytest.MonkeyPatch.context() as mp:
                mp.setenv("HYBRIDSEC_CUSTOM_PROGRAMS", "curl")
                stale = start_run(client, tools=["nmap", "pytestcheck"])
                listed = client.get("/api/tools/custom").json()["tools"][0]
                offered = start_run(client, tools=["masscan"]).json()["detail"]
        finally:
            settings.reload()
        assert stale.status_code == 400 and stale.json()["detail"].startswith(
            "pytestcheck no longer passes the registration rules: Program: hybridsec-test-missing-program is not on the "
            "list of allowed programs (curl).")
        assert listed["installed"] is False and listed["refused"] is True
        assert "not on the list of allowed programs" in listed["install_hint"]
        # The unknown-tool error offers only the custom tools a run can use: not one the rules now refuse.
        assert offered == "Unknown tool(s): masscan. Supported: nmap, whatweb, nikto."
        assert start_run(client, tools=["masscan"]).json()["detail"] == \
            "Unknown tool(s): masscan. Supported: nmap, whatweb, nikto, pytestcheck."
        # Nor a stored row whose name registration would have written another way (HDR) or that is a built-in tool's;
        # a run that names that tool is told to delete the row, which cannot be registered again under its name.
        stored = custom.validate_definition(CustomToolCreate(**CUSTOM_BODY), custom.allowed_programs(
            settings.custom_programs), datetime.now(timezone.utc), look_up=False)
        with storage.connect() as conn:
            for name in ("HDR", "nmap"):
                conn.execute("INSERT INTO custom_tools (name, created_at, document) VALUES (?, ?, ?)",
                             (name, stored.created_at.isoformat(),
                              stored.model_copy(update={"name": name}).model_dump_json()))
        assert start_run(client, tools=["nmap", "HDR"]).json()["detail"] == \
            "Unknown tool(s): HDR. Supported: nmap, whatweb, nikto, pytestcheck."
        clash = start_run(client, tools=["nmap", "pytestcheck"])
        assert clash.status_code == 400 and clash.json()["detail"] == (
            "A stored custom tool is named nmap, like the built-in tool, so the run cannot tell them apart. Delete "
            "that custom tool on the Custom tools page, then start the run again.")
        assert storage.delete_custom_tool("HDR") and storage.delete_custom_tool("nmap")
        assert client.delete("/api/tools/custom/pytestcheck").status_code == 204
        assert client.get(f"/api/runs/{run['id']}").json()["custom_tools"] == run["custom_tools"]
    finally:
        for name in ("pytestcheck", "HDR", "nmap"):
            storage.delete_custom_tool(name)


# --- Execute request validation -------------------------------------------------------------------

def test_live_run_without_nmap_is_rejected(client):
    """A live run whose first tool is not installed is refused before anything starts."""
    if shutil.which("nmap"):
        pytest.skip("nmap is installed; the test-suite never launches real scans")
    resp = start_run(client, simulate=False, timeout_seconds=30)
    assert resp.status_code == 400 and "not installed" in resp.json()["detail"]


def test_execute_rejects_unknown_tools_and_ranges_without_nmap(client):
    """Unknown tools and network ranges without Nmap are refused; leaving out the time budget uses the default."""
    resp = start_run(client, tools=["nikt0"])
    assert resp.status_code == 400 and "Unknown tool" in resp.json()["detail"]
    resp = start_run(client, tools=["x" * 20000])  # an unknown name is echoed cut to 80 characters
    assert resp.status_code == 400 and "x" * 80 in resp.json()["detail"] and "x" * 81 not in resp.json()["detail"]
    resp = client.post("/api/ai/plan", json={"tools": ["x" * 20000], "objective": "Plan a scan of a lab host."})
    assert resp.status_code == 400 and "x" * 80 in resp.json()["detail"] and "x" * 81 not in resp.json()["detail"]
    # Many unknown names: each once, at most five of them, then a count of the rest.
    resp = start_run(client, tools=[f"tool{i:04d}" for i in range(5000)] + ["tool0000"])
    detail = resp.json()["detail"]
    assert resp.status_code == 400 and len(detail) < 200 and "tool0004 and 4995 more." in detail
    resp = start_run(client, target="192.168.1.0/24", tools=["whatweb"])
    assert resp.status_code == 400 and "port-scan" in resp.json()["detail"]
    resp = start_run(client)
    assert resp.status_code == 202
    wait_for_run(client, resp.json()["id"])


# --- Run lifecycle and robustness -----------------------------------------------------------------

def test_interrupted_runs_are_failed_on_startup(client):
    """Runs left "running" by a crash or restart are marked failed when the server starts again."""
    # `client` is requested so that the app's startup has created the database tables.
    stuck = make_run(id="stuck00000001", status="running", started_at=datetime.now(timezone.utc),
                     stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                             StageResult(stage="web_fingerprint", tool="whatweb", status="running")],
                     ports=[PortFinding(host="10.10.20.5", port=22, service="ssh")])
    storage.save_run(stuck)
    assert storage.fail_stale_runs(summarize=hybrid.summarize) >= 1
    recovered = storage.get_run("stuck00000001")
    assert recovered.status == "failed" and "restarted" in recovered.error
    assert recovered.stages[1].status == "failed" and recovered.finished_at is not None
    # The port the finished scan saved is counted, as the startup recovery in app/main.py arranges.
    assert recovered.summary.open_ports == 1 and recovered.summary.hosts_up == 1
    assert recovered.summary.partial is False  # a failed run, not a partial one
    assert "fail_stale_runs(summarize=summarize_run)" in inspect.getsource(app_main.lifespan)
    storage.delete_run("stuck00000001")


def test_concurrent_run_cap(client):
    """At the concurrent-run cap a new run gets 429, and an executing run cannot be deleted."""
    # Occupy every slot with placeholder runs, the way RunManager.create() does (under the manager's lock).
    placeholders = [make_run(id=f"busy{i:08d}", status="running") for i in range(settings.max_concurrent_runs)]
    with hybrid.manager._lock:
        for run in placeholders:
            hybrid.manager._active[run.id] = run
    try:
        resp = start_run(client)
        assert resp.status_code == 429 and "already executing" in resp.json()["detail"]
        assert client.delete(f"/api/runs/{placeholders[0].id}").status_code == 409
    finally:
        with hybrid.manager._lock:
            for run in placeholders:
                hybrid.manager._active.pop(run.id, None)


# --- Stage handlers with a faked scanner ----------------------------------------------------------

def test_nmap_unresolvable_target_fails_stage(monkeypatch):
    """An unresolvable target fails the Nmap stage with a clear message."""
    fake_scanner(monkeypatch, stdout='<?xml version="1.0"?><nmaprun></nmaprun>',
                 stderr='Failed to resolve "nohost.invalid".\nWARNING: No targets were specified, so 0 hosts scanned.')
    run = make_run(id="nores0000001", target="nohost.invalid", status="running",
                   stages=[StageResult(stage="port_scan", tool="nmap")])
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "failed" and "could not resolve" in stage.error


def test_nmap_host_timeout_is_reported(monkeypatch):
    """A host that hit Nmap's --host-timeout fails the stage and says so."""
    fake_scanner(monkeypatch, stdout='<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/>'
                                     '<address addr="10.0.0.5" addrtype="ipv4"/></host></nmaprun>')
    run = make_run(id="nmapto000001", target="10.0.0.5", status="running",
                   stages=[StageResult(stage="port_scan", tool="nmap")])
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "failed" and "host timeout" in stage.error
    assert "--host-timeout" in stage.command and "-6" not in stage.command


def test_ipv6_target_gets_nmap_v6_flag(monkeypatch):
    """IPv6 targets are scanned with nmap -6."""
    fake_scanner(monkeypatch, stdout='<?xml version="1.0"?><nmaprun><host><status state="up"/>'
                                     '<address addr="::1" addrtype="ipv6"/></host></nmaprun>')
    run = make_run(id="v6000000001", target="::1", status="running",
                   stages=[StageResult(stage="port_scan", tool="nmap")])
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert " -6 " in stage.command and stage.status == "completed"


def test_web_stage_fails_when_no_url_responds(monkeypatch):
    """WhatWeb fails its stage when no URL answers, and unreachable URLs do not count as web services."""
    fake_scanner(monkeypatch, exit_code=1, stderr="ERROR Opening: connection refused")
    run = make_run(id="web000000001", target="10.9.9.9", status="running", tools=["nmap", "whatweb"],
                   stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                           StageResult(stage="web_fingerprint", tool="whatweb")])
    context = {"web_ports": [PortFinding(host="10.9.9.9", port=80, service="http", is_web=True)],
               "deadline": time.monotonic() + 100}
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, context, stage_index=1)
    assert stage.status == "failed" and "no response" in stage.error
    assert run.web and run.web[0].reachable is False
    assert hybrid.summarize(run).web_services == 0


# --- Reports and comparison -----------------------------------------------------------------------

def test_csv_report_neutralises_formula_injection():
    """CSV cells that start like a spreadsheet formula get a leading quote, so they stay plain text."""
    run = make_run(id="csv000000001", tools=["nikto"],
                   vulns=[VulnFinding(url="http://127.0.0.1", severity="low",
                                      description="=HYPERLINK(\"http://evil.example\",\"click\")", reference="@cmd")])
    csv_text = render_csv(run)
    assert "'=HYPERLINK" in csv_text and "'@cmd" in csv_text
    assert ",=HYPERLINK" not in csv_text


def test_markdown_report_escapes_table_and_fence_breakers():
    """Pipes, HTML and code fences in tool output cannot break the structure of the Markdown report."""
    run = make_run(id="md0000000001", tools=["nikto"],
                   vulns=[VulnFinding(url="http://127.0.0.1", severity="low", description="a | b <script>x</script>")],
                   log=["```", "normal line"])
    md = render_markdown(run)
    assert "a \\| b &lt;script&gt;" in md
    assert md.count("\n```\n") == 2  # only the opening and closing fence of the log block


def test_compare_ignores_volatile_urls_and_numbers():
    """Session ids in URLs and changing numbers in Nikto messages are not reported as differences."""
    def run_with(run_id: str, session: int, inode: int, size: int) -> Run:
        return make_run(id=run_id, target="h", tools=["whatweb", "nikto"],
                        web=[WebFinding(url=f"http://h/?sid={session}", host="h", port=80, status_code=200,
                                        technologies=[{"name": "nginx", "version": "1.18.0"}])],
                        vulns=[VulnFinding(url="http://h/", severity="low",
                                           description=f"Server leaks inode {inode} via ETag, size {size}")])

    diff = compare_runs(run_with("cmp000000001", 111, 12345, 777), run_with("cmp000000002", 999, 67890, 778))
    assert diff.tech_added == [] and diff.tech_removed == []
    assert diff.vulns_added == [] and diff.vulns_removed == []


# --- Settings API and the .env file ---------------------------------------------------------------

def test_settings_roundtrip(client):
    """Settings are validated, written to .env and applied without a restart; secrets are never echoed."""
    env_path = Path(os.environ["HYBRIDSEC_ENV_FILE"])
    view = client.get("/api/settings").json()
    # Guard against ever touching the developer's real .env from the test-suite.
    assert Path(view["env_file"]) == env_path
    assert view["env_file_writable"] is True
    assert view["anthropic_key_configured"] is False and view["openai_key_configured"] is False

    resp = client.put("/api/settings", json={
        "ai_provider": "rules",
        "allowed_targets": ["127.0.0.1", " 10.0.0.0/8 ", "*.Lab.Local", ""],
        "allow_simulation": True,
        "max_timeout_seconds": 600,
    })
    assert resp.status_code == 200, resp.text
    view = resp.json()
    assert view["ai_provider_setting"] == "rules" and view["ai_provider_resolved"] == "rules"
    assert view["allowed_targets"] == ["127.0.0.1", "10.0.0.0/8", "*.lab.local"]
    assert view["max_timeout_seconds"] == 600
    env_text = env_path.read_text()
    assert "HYBRIDSEC_ALLOWED_TARGETS=127.0.0.1,10.0.0.0/8,*.lab.local" in env_text
    assert "HYBRIDSEC_MAX_TIMEOUT=600" in env_text

    # A key is stored, reported only as configured, and can be cleared again.
    resp = client.put("/api/settings", json={"anthropic_api_key": "sk-ant-test-not-a-real-key-0000"})
    assert resp.status_code == 200 and resp.json()["anthropic_key_configured"] is True
    assert "sk-ant-test-not-a-real-key-0000" not in resp.text
    assert client.get("/api/health").json()["ai_provider"] == "rules"  # provider forced to rules above
    resp = client.put("/api/settings", json={"anthropic_api_key": ""})
    assert resp.json()["anthropic_key_configured"] is False
    assert "ANTHROPIC_API_KEY=\n" in env_path.read_text()

    # Invalid values are refused; the execute endpoint honours the allow-list without a restart.
    assert client.put("/api/settings", json={"allowed_targets": ["bad host!"]}).status_code == 400
    assert client.put("/api/settings", json={"anthropic_api_key": "has spaces in it"}).status_code == 400
    assert client.put("/api/settings", json={"openai_model": "gpt\nOPENAI_API_KEY=x"}).status_code == 400
    assert client.put("/api/settings", json={"openai_base_url": "ftp://x"}).status_code == 400
    assert client.put("/api/settings", json={"openai_base_url": "https://api.openai.com/v1 extra words"}).status_code == 400
    timeouts = {"default_timeout_seconds": 5000, "max_timeout_seconds": 600}
    assert client.put("/api/settings", json=timeouts).status_code == 400
    client.put("/api/settings", json={"allowed_targets": ["127.0.0.1"]})
    denied = start_run(client, target="10.10.10.10")
    assert denied.status_code == 400 and "outside the allowed scope" in denied.json()["detail"]
    client.put("/api/settings", json={"allowed_targets": []})


def test_settings_test_planner_uses_rules(client):
    """The Test planner endpoint reports which planner answered and the steps it planned."""
    client.put("/api/settings", json={"ai_provider": "rules"})
    result = client.post("/api/settings/test-planner").json()
    assert result["ok"] is True and result["provider"] == "rules"
    assert result["steps"] == ["1. nmap (port_scan)", "2. whatweb (web_fingerprint)"]


def test_blank_env_values_do_not_mask_process_environment(monkeypatch):
    """A blank KEY= line in .env does not hide a value set in the process environment, but a real value wins."""
    monkeypatch.setenv("HYBRIDSEC_MAX_TOP_PORTS", "777")
    update_env_file(ENV_FILE, {"HYBRIDSEC_MAX_TOP_PORTS": ""})
    settings.reload()
    assert settings.max_top_ports == 777
    update_env_file(ENV_FILE, {"HYBRIDSEC_MAX_TOP_PORTS": "900"})
    settings.reload()
    assert settings.max_top_ports == 900
    update_env_file(ENV_FILE, {"HYBRIDSEC_MAX_TOP_PORTS": ""})


def test_env_writer_handles_duplicates_quotes_and_bad_values(tmp_path):
    """The .env writer keeps one line per key, quotes special values, and refuses line breaks and single quotes."""
    env = tmp_path / "x.env"
    env.write_text("# header\nA=1\nB=keep\nA=2\n", encoding="utf-8")
    update_env_file(env, {"A": "3", "C": "$HOME and spaces"})
    text = env.read_text(encoding="utf-8")
    assert text.count("\nA=") + text.startswith("A=") == 1 and "A=3" in text and "# header" in text
    values = dotenv_values(env)
    assert values["A"] == "3" and values["B"] == "keep" and values["C"] == "$HOME and spaces"
    with pytest.raises(EnvValueError):
        update_env_file(env, {"D": "line\nbreak"})
    with pytest.raises(EnvValueError):
        update_env_file(env, {"D": "it's"})


# --- Parsers --------------------------------------------------------------------------------------

def test_is_web_service_tls_requires_http_like_inner_service():
    """TLS alone does not make a port a web service: IMAPS, SMTPS and LDAPS are not web."""
    assert parsers.is_web_service(443, "http", "ssl")
    assert parsers.is_web_service(8443, "", "ssl")
    assert parsers.is_web_service(8443, "unknown", "ssl")
    assert not parsers.is_web_service(993, "imaps", "ssl")
    assert not parsers.is_web_service(465, "smtps", "ssl")
    assert not parsers.is_web_service(636, "ldapssl", "ssl")


def test_classify_nikto_uses_word_boundaries():
    """Nikto severity keywords match whole words only ("rce" must not match "source")."""
    assert parsers.classify_nikto("/server-status: restrict access to allowed sources") == "info"
    assert parsers.classify_nikto("Uncommon header 'x-resource-id' found") == "info"
    assert parsers.classify_nikto("Possible RCE via unsanitised parameter") == "critical"
    assert parsers.classify_nikto("Directory indexing found.") == "high"


def test_whatweb_keeps_probed_url_and_marks_unreachable():
    """WhatWeb results keep the probed URL, record where redirects ended, and mark silent URLs unreachable."""
    raw = ('[{"target":"https://sso.example/login?sid=1","http_status":302,'
           '"plugins":{"HTTPServer":{"string":["nginx"]}}}]')
    finding = parsers.parse_whatweb_json(raw, "http://10.0.0.5", "10.0.0.5", 80)
    assert finding.url == "http://10.0.0.5" and finding.final_url == "https://sso.example/login?sid=1"
    assert finding.reachable is True
    empty = parsers.parse_whatweb_json("", "http://10.0.0.5:8080", "10.0.0.5", 8080)
    assert empty.reachable is False and empty.status_code is None


NMAP_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.168.1.5" addrtype="ipv4"/><hostnames><hostname name="lab.local"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" tunnel="ssl"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp"/></port>
</ports></host></nmaprun>"""


def test_parse_nmap_xml():
    """Nmap XML yields only the open ports, flags web services, and gives TLS services an https URL."""
    ports, up = parsers.parse_nmap_xml(NMAP_XML)
    assert up == 1
    assert [(p.port, p.is_web) for p in ports] == [(22, False), (443, True)]
    assert ports[1].service == "ssl/http"
    assert parsers.url_for(ports[1]) == "https://192.168.1.5"


def test_parse_whatweb_json():
    """WhatWeb JSON yields the status, the title and the technologies, minus connection-only plugins."""
    raw = ('[{"target":"http://192.168.1.5","http_status":200,"plugins":{"HTTPServer":{"string":["nginx/1.18.0"]},'
           '"Title":{"string":["Welcome"]},"PHP":{"version":["7.4.33"]},"Country":{"string":["RESERVED"]}}}]')
    finding = parsers.parse_whatweb_json(raw, "http://192.168.1.5", "192.168.1.5", 80)
    assert finding.status_code == 200 and finding.title == "Welcome"
    names = {t["name"] for t in finding.technologies}
    assert "PHP" in names and "HTTPServer" in names and "Country" not in names


def test_parse_nikto_json_and_text():
    """Nikto findings are read from its JSON report, and from its text output without the banner lines."""
    raw = ('[{"host":"192.168.1.5","vulnerabilities":[{"id":"999986","url":"/manager/html",'
           '"msg":"Tomcat Manager found"}]}]')
    vulns = parsers.parse_nikto_json(raw, "http://192.168.1.5:8080")
    assert vulns[0].url.endswith("/manager/html") and vulns[0].severity == "high"
    text = "+ Target IP: 1.2.3.4\n+ The anti-clickjacking X-Frame-Options header is not present.\n+ 1 host(s) tested"
    assert len(parsers.parse_nikto_text(text, "http://x")) == 1
    # Output holding only the banner and error lines examined nothing; a completed scan without findings is clean.
    unresolved = "- Nikto v2.1.6\n---------\n+ ERROR: Cannot resolve hostname 'x'\n+ 0 host(s) tested\n"
    assert parsers.parse_nikto_text(unresolved, "http://x") == []
    assert parsers.nikto_text_problem(unresolved) == "ERROR: Cannot resolve hostname 'x'"
    assert parsers.nikto_text_problem("- Nikto v2.1.6\n---------\n") == "no scan output (banner only)"
    closed = "- Nikto v2.5.0\n+ No web server found on 10.10.20.5:80\n+ 0 host(s) tested\n"
    assert parsers.parse_nikto_text(closed, "http://10.10.20.5") == []
    assert parsers.nikto_stopped_early(closed) == "No web server found on 10.10.20.5:80"
    assert parsers.nikto_text_problem(text) is None
