"""Regression tests for the second review round: one test per fixed defect, so none of them can come back.

Each test names the behaviour it protects and its docstring states the requirement it checks. Like the rest of
the suite the tests run offline: scanners are never launched (the only child processes are short-lived
`python -c` commands and, when it is installed, `node` evaluating a dashboard helper), the planner's provider
call is replaced with canned answers, and every .env write goes to the private file tests/test_api.py sets up.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from dotenv import dotenv_values
from fastapi.testclient import TestClient

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import config, hybrid, planner, storage
from app import main as app_main
from app.config import BASE_DIR, ENV_FILE, settings
from app.envfile import EnvValueError, update_env_file, validate_value
from app.main import app
from app.reports import render_csv
from app.routers.settings_api import require_local
from app.schemas import ExecuteRequest, Plan, PlanStep, SafetyControls, WebFinding
from app.security import normalize_target
from app.tools import parsers, runner
from app.tools.registry import TOOLS
from app.tools.runner import CommandResult
from tests.test_api import make_run, start_run, wait_for_run

# Safety net: every .env write below must go to the throwaway file that tests/test_api.py configured.
assert Path(os.environ["HYBRIDSEC_ENV_FILE"]) == ENV_FILE and ENV_FILE.name == "test.env"

DASHBOARD = BASE_DIR / "dashboard"
UTF8_BOM = b"\xef\xbb\xbf"
BOM_TEXT = chr(0xFEFF)  # the byte-order mark as the character it decodes to
# Unicode separators that str.splitlines() treats as line breaks although python-dotenv does not. They are built
# with chr() so that no editor or tool can silently turn an escape sequence into an invisible literal character.
NEXT_LINE = chr(0x85)
LINE_SEPARATOR = chr(0x2028)
PARAGRAPH_SEPARATOR = chr(0x2029)
# Harmless stand-ins for a scanner process: one that keeps running until it is killed, one that exits at once.
SLEEPING_CHILD = [sys.executable, "-c", "import time; time.sleep(30)"]
QUICK_CHILD = [sys.executable, "-c", "pass"]


# --- Fixtures and helpers -------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    # The TestClient's peer is "testclient", not a loopback IP, so the settings guard is overridden here.
    app.dependency_overrides[require_local] = lambda: None
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _settings_follow_the_real_environment():
    """After each test, re-read the settings so a monkeypatched environment or .env value never leaks."""
    yield
    settings.reload()


@pytest.fixture
def model_answers(monkeypatch):
    """Replace the planner's provider call with a queue of canned plans; no real AI provider is contacted."""
    answers: list[Plan] = []

    def fake_call_provider(provider, user_prompt):
        return answers.pop(0), "fake-model"

    monkeypatch.setattr(planner, "_call_provider", fake_call_provider)
    return answers


@pytest.fixture
def anthropic_provider(client):
    """Select the anthropic planner for one test and restore the rules planner afterwards."""
    assert client.put("/api/settings", json={"ai_provider": "anthropic"}).status_code == 200
    yield
    assert client.put("/api/settings", json={"ai_provider": "rules"}).status_code == 200


def _private_env_file() -> Path:
    """The private test .env, created empty when no test has written it yet (Settings skips a missing file)."""
    if not ENV_FILE.exists():
        ENV_FILE.write_text("", encoding="utf-8")
    return ENV_FILE


def _model_plan(*tools: str) -> Plan:
    """A plan shaped like a model's answer, with one step per given tool name (unknown names included)."""
    steps = [PlanStep(order=index, tool=tool, stage="port_scan", purpose=f"Run {tool}.")
             for index, tool in enumerate(tools, start=1)]
    return Plan(summary="Plan written by the fake model of the regression tests.", workflow=steps,
                inputs=["target"], outputs=["findings"], safety_controls=SafetyControls(), limitations=[])


def _wait_for_live_process(timeout: float = 5.0) -> None:
    """Block until run_command() has registered a child process, or fail the test."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with runner._live_lock:
            started = bool(runner._live)
        if started:
            return
        time.sleep(0.01)
    pytest.fail("the child process did not register as live in time")


# --- A. Scanner runner: shutdown must stop new processes --------------------------------------------

def test_run_command_refuses_to_start_a_process_once_shutdown_began(monkeypatch):
    """Requirement: after terminate_all() no worker thread may launch another scanner."""
    monkeypatch.setattr(runner, "_shutting_down", False)
    runner.terminate_all()
    with pytest.raises(OSError, match="shutting down"):
        runner.run_command(QUICK_CHILD, timeout=5)
    with runner._live_lock:
        assert not runner._live


def test_terminate_all_kills_the_live_process_and_its_worker_finishes(monkeypatch):
    """Requirement: shutdown kills every running scanner so none outlives the server, and reports how many."""
    monkeypatch.setattr(runner, "_shutting_down", False)
    outcome = {}

    def worker():
        outcome["result"] = runner.run_command(SLEEPING_CHILD, timeout=60)

    thread = threading.Thread(target=worker, daemon=True, name="round2-sleeper")
    thread.start()
    _wait_for_live_process()
    assert runner.terminate_all() == 1
    thread.join(timeout=5)
    assert not thread.is_alive(), "the worker is still waiting on a process that should have been killed"
    result = outcome["result"]
    assert result.exit_code not in (0, None) and result.timed_out is False
    assert result.interrupted is True  # so the pipeline records the shutdown instead of a tool failure
    with runner._live_lock:
        assert not runner._live


def test_start_tool_reports_a_failed_start_while_shutting_down(monkeypatch):
    """Requirement: a stage asked to run a tool during shutdown gets a failed result, not a crash or a process;
    and a run whose tool the shutdown killed or kept from starting is recorded as interrupted by the shutdown
    (not as "nmap exited with code 1", and never as completed), with the stages that never ran skipped."""
    storage.init_db()  # the runs are saved; the tables must exist when this test runs on its own
    monkeypatch.setattr(runner, "_shutting_down", False)
    runner.terminate_all()
    result = hybrid._start_tool(QUICK_CHILD, timeout=5)
    assert result.exit_code == hybrid.START_FAILED_EXIT_CODE
    assert "shutting down" in result.stderr and result.stdout == ""
    with runner._live_lock:
        assert not runner._live
    context: dict = {}
    assert hybrid._start_tool(QUICK_CHILD, timeout=5, context=context).exit_code == hybrid.START_FAILED_EXIT_CODE
    assert context == {"interrupted": True}

    runner.accept_new_processes()
    killed = CommandResult(command=["nmap"], exit_code=1, stdout="", stderr="", duration_seconds=0.5, interrupted=True)
    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", lambda command, timeout: killed)
    manager = hybrid.RunManager()
    request = ExecuteRequest(target="10.10.20.5", authorized=True)
    queued = manager.create(request, request.target, ["nmap", "whatweb"], None, 60)
    deadline = time.monotonic() + 10
    while manager.is_active(queued.id) and time.monotonic() < deadline:
        time.sleep(0.02)
    try:
        stored = storage.get_run(queued.id)
        assert stored.status == "failed" and stored.error == hybrid.SHUTDOWN_REASON
        assert [s.status for s in stored.stages] == ["failed", "skipped"]
        assert stored.stages[0].error == "nmap was stopped: the server is shutting down"
        assert stored.stages[1].error == hybrid.SHUTDOWN_REASON
        assert any(line.endswith(hybrid.SHUTDOWN_REASON) for line in stored.log)
    finally:
        storage.delete_run(queued.id)

    # Nmap finished, then the shutdown stopped WhatWeb: the run still counts the port Nmap found, so its KPIs
    # and reports agree with its Ports tab instead of showing zeros.
    nmap_xml = ('<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
                '<address addr="10.10.20.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
                '<state state="open"/><service name="http" product="nginx"/></port></ports></host></nmaprun>')

    def scan_then_shutdown(command, timeout):
        if os.path.basename(command[0]) == "nmap":
            return CommandResult(command=command, exit_code=0, stdout=nmap_xml, stderr="", duration_seconds=0.5)
        return killed

    monkeypatch.setattr(hybrid, "run_command", scan_then_shutdown)
    second = manager.create(request, request.target, ["nmap", "whatweb", "nikto"], None, 60)
    deadline = time.monotonic() + 10
    while manager.is_active(second.id) and time.monotonic() < deadline:
        time.sleep(0.02)
    try:
        stored = storage.get_run(second.id)
        assert stored.status == "failed" and stored.error == hybrid.SHUTDOWN_REASON
        assert [s.status for s in stored.stages] == ["completed", "failed", "skipped"]
        assert (stored.summary.open_ports, stored.summary.hosts_up) == (1, 1) and len(stored.ports) == 1
        assert stored.summary.partial is False and stored.summary.highlights == []  # failed, not partial or clean
    finally:
        storage.delete_run(second.id)
    # The app's shutdown waits for executing runs to save that state before the process exits.
    assert manager.wait_until_idle(1.0) is True
    with manager._lock:
        manager._active["placeholder"] = stored
    try:
        assert manager.wait_until_idle(0.05) is False
    finally:
        with manager._lock:
            manager._active.pop("placeholder")
    assert "run_manager.wait_until_idle" in inspect.getsource(app_main.lifespan)


def test_accept_new_processes_re_arms_the_runner(monkeypatch):
    """Requirement: after accept_new_processes() the runner starts scanner processes again."""
    monkeypatch.setattr(runner, "_shutting_down", False)
    runner.terminate_all()
    runner.accept_new_processes()
    result = runner.run_command(QUICK_CHILD, timeout=30)
    assert result.exit_code == 0 and result.timed_out is False


def test_app_startup_clears_the_shutdown_flag(monkeypatch):
    """Requirement: a new application lifespan in the same process re-arms the runner at startup."""
    monkeypatch.setattr(runner, "_shutting_down", False)
    runner.terminate_all()
    assert runner._shutting_down is True
    with TestClient(app, base_url="http://localhost") as fresh_client:
        assert runner._shutting_down is False
        assert fresh_client.get("/api/health").status_code == 200
    # Startup also arranges for the scanners to be killed when an exit skips the shutdown (a forced exit).
    assert runner._cleanup_installed is True


# --- B. Highlights: IIS version disclosure ---------------------------------------------------------

def test_iis_version_disclosure_is_highlighted():
    """Requirement: a disclosed Microsoft-IIS version is a highlight like any other version-sensitive product."""
    run = make_run(id="iis000000001", target="10.10.20.5", tools=["whatweb"],
                   web=[WebFinding(url="http://10.10.20.5", host="10.10.20.5", port=80, status_code=200,
                                   technologies=[{"name": "Microsoft-IIS", "version": "10.0"}])])
    assert "microsoft-iis" in hybrid.VERSION_SENSITIVE
    assert "Microsoft-IIS 10.0 disclosed at http://10.10.20.5" in hybrid.summarize(run).highlights


# --- C. Health endpoint under an unknown Host header -----------------------------------------------

def test_health_under_unknown_host_reports_liveness_only(client):
    """Requirement: an uptime check with a foreign Host header learns only that the server is up."""
    resp = client.get("/api/health", headers={"Host": "evil.example"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    # Only GET: any other method under an unknown name gets the guard's 400, never a better answer than the
    # dashboard's own name would give (405).
    for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD"):
        assert client.request(method, "/api/health", headers={"Host": "evil.example"}).status_code == 400, method


def test_health_under_trusted_host_keeps_the_full_summary(client):
    """Requirement: the dashboard (a trusted Host) still receives the planner, tools, limits and allow-list."""
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert {"ai_provider", "allowed_targets", "tools", "limits"} <= set(body)


def test_other_paths_under_unknown_host_are_still_rejected(client):
    """Requirement: the health exception does not weaken the DNS-rebinding guard for any other path."""
    assert client.get("/api/runs", headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


# --- D. .env writer: Unicode line separators -------------------------------------------------------

@pytest.mark.parametrize("separator", ["\n", "\r", NEXT_LINE, LINE_SEPARATOR, PARAGRAPH_SEPARATOR])
def test_validate_value_rejects_every_line_separator(separator):
    """Requirement: a value holding any line separator python-dotenv or str.splitlines() knows is refused."""
    with pytest.raises(EnvValueError, match="line breaks or control characters"):
        validate_value(f"claude{separator}OPENAI_MODEL=other", "Anthropic model")


@pytest.mark.parametrize("separator", [NEXT_LINE, LINE_SEPARATOR, PARAGRAPH_SEPARATOR])
def test_env_file_writer_splits_only_on_real_line_breaks(tmp_path, separator):
    """Requirement: a quoted value that already holds a Unicode separator stays one line and never becomes a new key."""
    env = tmp_path / "lab.env"
    env.write_text(f"A='x{separator}y'\nB=1\n", encoding="utf-8")
    update_env_file(env, {"B": "2"})
    assert env.read_text(encoding="utf-8") == f"A='x{separator}y'\nB=2\n"
    assert dotenv_values(env) == {"A": f"x{separator}y", "B": "2"}


@pytest.mark.parametrize("field,value", [
    ("anthropic_model", f"claude{LINE_SEPARATOR}opus"),
    ("openai_model", f"gpt{NEXT_LINE}mini"),
    ("openai_base_url", f"https://lab.example.edu{PARAGRAPH_SEPARATOR}/v1"),
])
def test_settings_api_rejects_unicode_line_separators(client, field, value):
    """Requirement: the Settings API refuses text that could split into an extra KEY=value line in .env."""
    resp = client.put("/api/settings", json={field: value})
    assert resp.status_code == 400
    assert "line breaks or control characters" in resp.json()["detail"]


# --- E. Settings: trusted hosts, SDK credentials, locked .env --------------------------------------

def test_shell_bind_host_is_trusted_even_when_env_file_binds_loopback(client, monkeypatch):
    """Requirement: the address run.sh/run.ps1 bind through the shell passes the Host check although .env says 127.0.0.1."""
    env_file = _private_env_file()
    previous = dotenv_values(env_file).get("HYBRIDSEC_HOST") or ""
    update_env_file(env_file, {"HYBRIDSEC_HOST": "127.0.0.1"})
    monkeypatch.setenv("HYBRIDSEC_HOST", "10.10.20.5")
    try:
        assert dotenv_values(env_file)["HYBRIDSEC_HOST"] == "127.0.0.1"
        settings.reload()
        assert "10.10.20.5" in settings.allowed_hosts
        assert client.get("/", headers={"Host": "10.10.20.5:8000"}).status_code == 200
        assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
    finally:
        update_env_file(env_file, {"HYBRIDSEC_HOST": previous})


@pytest.mark.parametrize("bind_address", ["0.0.0.0", "::"])
def test_wildcard_bind_address_is_not_a_trusted_host_name(monkeypatch, bind_address):
    """Requirement: a wildcard bind address is not a host name, so it never enters the Host allow-list."""
    monkeypatch.setenv("HYBRIDSEC_HOST", bind_address)
    settings.reload()
    assert bind_address not in settings.allowed_hosts
    assert "localhost" in settings.allowed_hosts


@pytest.mark.parametrize("auto_discoverable,active_profile,expected", [
    (False, False, False),
    (True, False, True),
    (False, True, True),
])
def test_anthropic_credentials_are_detected_through_the_sdk(monkeypatch, auto_discoverable, active_profile, expected):
    """Requirement: without a key in .env, the Anthropic SDK decides whether it can authenticate (env or profile)."""
    sdk_credentials = pytest.importorskip("anthropic.lib.credentials._constants")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(sdk_credentials, "_has_auto_discoverable_credentials", lambda: auto_discoverable)
    monkeypatch.setattr(sdk_credentials, "_has_active_profile_config", lambda: active_profile)
    assert settings.anthropic_credentials_present() is expected


def test_anthropic_auth_token_counts_as_credentials(monkeypatch, tmp_path):
    """Requirement: an ANTHROPIC_AUTH_TOKEN in the environment is enough for the planner to pick Anthropic."""
    sdk_credentials = pytest.importorskip("anthropic.lib.credentials._constants")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    monkeypatch.setattr(sdk_credentials, "_has_auto_discoverable_credentials", lambda: False)
    monkeypatch.setattr(sdk_credentials, "_has_active_profile_config", lambda: False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    assert settings.anthropic_credentials_present() is False
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "test-only-token")
    assert settings.anthropic_credentials_present() is True

    # The preflight checklist reports the same credentials, a login profile included, without loading the app.
    spec = importlib.util.spec_from_file_location("preflight_under_test", BASE_DIR / "scripts" / "preflight.py")
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    assert preflight._anthropic_login_profile() is False  # it asks the SDK, as app/config.py does
    monkeypatch.setattr(sdk_credentials, "_has_active_profile_config", lambda: True)
    assert preflight._anthropic_login_profile() is True
    (tmp_path / ".env").write_text("HYBRIDSEC_AI_PROVIDER=auto\n", encoding="utf-8")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    for profile, detail in ((True, "provider=auto, Anthropic login profile found"),
                            (False, "provider=auto, no API key, token or login profile found (rules planner will answer)")):
        monkeypatch.setattr(preflight, "results", [])
        monkeypatch.setattr(preflight, "_anthropic_login_profile", lambda found=profile: found)
        preflight.check_env_file()
        assert preflight.results[0][1:] == ("Configuration (.env)", detail)


def test_env_file_read_is_retried_after_a_transient_permission_error(monkeypatch):
    """Requirement: a .env locked for a moment by a concurrent save is re-read instead of failing the request."""
    env_file = _private_env_file()
    calls = []

    def flaky_dotenv_values(path):
        calls.append(path)
        if len(calls) == 1:
            raise PermissionError("locked by another process")
        return {"HYBRIDSEC_MAX_TOP_PORTS": "123"}

    monkeypatch.setattr(config, "dotenv_values", flaky_dotenv_values)
    settings.reload()
    assert settings.max_top_ports == 123
    assert calls == [env_file, env_file]


def test_unreadable_env_file_keeps_the_values_read_last_time(monkeypatch):
    """Requirement: when .env stays unreadable or is not valid UTF-8, reload() keeps the previous settings instead
    of raising."""
    _private_env_file()
    monkeypatch.setattr(config, "dotenv_values", lambda path: {"HYBRIDSEC_MAX_TOP_PORTS": "123"})
    settings.reload()
    assert settings.max_top_ports == 123

    def always_locked(path):
        raise PermissionError("locked by another process")

    monkeypatch.setattr(config, "dotenv_values", always_locked)
    settings.reload()  # must not raise
    assert settings.max_top_ports == 123

    def saved_as_ansi(path):  # a Windows editor saved .env as ANSI or UTF-16: not transient, same fallback
        raise UnicodeDecodeError("utf-8", bytes([0xE9]), 0, 1, "invalid start byte")

    monkeypatch.setattr(config, "dotenv_values", saved_as_ansi)
    settings.reload()  # must not raise either
    assert settings.max_top_ports == 123


# --- F. Planner: only registry tools survive -------------------------------------------------------

def test_plan_schema_restricts_tool_to_registry_names():
    """Requirement: the structured-output schema only lets a model name tools HybridSec can execute."""
    tool_property = planner.PLAN_SCHEMA["properties"]["workflow"]["items"]["properties"]["tool"]
    assert tool_property["enum"] == list(TOOLS) == ["nmap", "whatweb", "nikto"]


def test_normalize_plan_rejects_a_plan_without_allowed_tools():
    """Requirement: a model plan whose steps all name unknown tools is an error, never an empty workflow."""
    request = planner.PlanRequest(tools=["nmap", "whatweb"], objective="Round-2 test: plan a hybrid scan.")
    with pytest.raises(ValueError, match="none of the allowed tools"):
        planner._normalize_plan(_model_plan("what web", "nikt0"), request)


@pytest.mark.usefixtures("anthropic_provider")
def test_model_plan_keeps_only_registry_tools_and_mirrors_them_in_the_request(client, model_answers):
    """Requirement: an unknown tool in a model step is dropped, and the saved request lists only the steps kept."""
    model_answers.append(_model_plan("nmap", "what web"))
    resp = client.post("/api/ai/plan", json={"tools": ["nmap", "whatweb"],
                                             "objective": "Round-2 test: plan a hybrid scan of a lab host."})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["provider"] == "anthropic" and body["model"] == "fake-model"
    # The note names the dropped step, because the plan's other text (summary, outputs) may still mention it.
    assert body["note"].startswith("The model added what web, which was not among the selected tools, so it was "
                                   "removed from the workflow.")
    assert [step["tool"] for step in body["plan"]["workflow"]] == ["nmap"]
    assert body["request"]["tools"] == ["nmap"]
    saved = client.get(f"/api/ai/plans/{body['id']}").json()
    assert saved["request"]["tools"] == ["nmap"]
    assert [step["tool"] for step in saved["plan"]["workflow"]] == ["nmap"]
    # The Test planner passes when the provider answered, even with such a note (a tool it added to the fixed
    # nmap + whatweb request): only a fallback to the rules planner is a failure.
    model_answers.append(_model_plan("nmap", "whatweb", "nikto"))
    tested = client.post("/api/settings/test-planner").json()
    assert (tested["ok"], tested["provider"], tested["model"]) == (True, "anthropic", "fake-model")
    assert tested["note"].startswith("The model added Nikto,")
    assert tested["steps"] == ["1. nmap (port_scan)", "2. whatweb (web_fingerprint)"]


@pytest.mark.usefixtures("anthropic_provider")
def test_model_plan_without_any_known_tool_falls_back_to_rules(client, model_answers):
    """Requirement: a model plan with no usable step is answered by the rules planner, and the note says why."""
    model_answers.append(_model_plan("what web", "nikt0"))
    resp = client.post("/api/ai/plan", json={"tools": ["nmap", "whatweb"],
                                             "objective": "Round-2 test: plan a hybrid scan of a lab host."})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["provider"] == "rules" and body["model"] is None
    assert "anthropic planner failed" in body["note"] and "none of the allowed tools" in body["note"]
    assert [step["tool"] for step in body["plan"]["workflow"]] == ["nmap", "whatweb"]


@pytest.mark.usefixtures("anthropic_provider")
def test_failed_refinement_keeps_the_previous_revision_with_a_note(client, model_answers):
    """Requirement: when refining a model plan fails, the new revision repeats the parent and explains why."""
    model_answers.append(_model_plan("nmap", "whatweb"))
    parent = client.post("/api/ai/plan", json={"tools": ["nmap", "whatweb"],
                                               "objective": "Round-2 test: plan a hybrid scan of a lab host."}).json()
    assert parent["provider"] == "anthropic"
    model_answers.append(_model_plan("what web"))  # the refinement names no tool HybridSec has
    resp = client.post(f"/api/ai/plans/{parent['id']}/refine", json={"feedback": "Swap WhatWeb for a new tool."})
    assert resp.status_code == 200, resp.text
    child = resp.json()
    assert child["parent_id"] == parent["id"] and child["revision"] == 2
    assert child["plan"] == parent["plan"]
    assert child["request"]["tools"] == parent["request"]["tools"] == ["nmap", "whatweb"]
    assert child["provider"] == "rules" and child["model"] is None
    assert "previous revision was kept" in child["note"] and "none of the allowed tools" in child["note"]


# --- G. Nikto parser: severities and finding URLs --------------------------------------------------

@pytest.mark.parametrize("message,severity", [
    ("Site appears vulnerable to the 'shellshock' vulnerability (CVE-2014-6271).", "critical"),
    ("RFI from RSnake's list detected.", "critical"),
    ("Possible backdoors found in /cgi-bin/", "critical"),
    ("/phpmyadmin/: phpMyAdmin directory found", "high"),
    ("Powered by an open source CMS", "info"),
])
def test_classify_nikto_grades_rfi_shellshock_phpmyadmin_and_plurals(message, severity):
    """Requirement: Nikto's RFI, Shellshock and phpMyAdmin findings are graded, plurals count, "source" is not "rce"."""
    assert parsers.classify_nikto(message) == severity


def test_nikto_finding_url_keeps_an_rfi_probe_path_on_the_scanned_host():
    """Requirement: a Nikto path that merely contains "http://" is joined onto the scanned URL; only a real URL is kept."""
    rfi_path = "/index.php?page=http://cirt.net/rfiinc.txt?"
    assert parsers._finding_url("http://10.10.20.5", rfi_path) == "http://10.10.20.5" + rfi_path
    assert parsers._finding_url("http://10.10.20.5", "https://10.10.20.5:8443/x") == "https://10.10.20.5:8443/x"
    report = json.dumps([{"host": "10.10.20.5", "vulnerabilities": [{"id": "999", "url": rfi_path,
                                                                       "msg": "RFI from RSnake's list"}]}])
    finding = parsers.parse_nikto_json(report, "http://10.10.20.5")[0]
    assert finding.url == "http://10.10.20.5" + rfi_path and finding.severity == "critical"


# --- H. Targets: single-address CIDR blocks --------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("10.10.20.5/32", "10.10.20.5"),
    ("fd00::5/128", "fd00::5"),
    ("10.10.20.0/24", "10.10.20.0/24"),
    ("fd00::/120", "fd00::/120"),
])
def test_single_address_block_normalizes_to_the_bare_address(raw, expected):
    """Requirement: a /32 or /128 is one host and is scanned as that address; larger blocks stay networks."""
    assert normalize_target(raw) == expected


def test_execute_records_the_bare_address_for_a_slash_32_target(client):
    """Requirement: a run requested for 10.10.20.5/32 is recorded and executed against 10.10.20.5."""
    resp = start_run(client, target="10.10.20.5/32")
    assert resp.status_code == 202, resp.text
    assert resp.json()["target"] == "10.10.20.5"
    run = wait_for_run(client, resp.json()["id"])
    assert run["target"] == "10.10.20.5" and run["status"] == "completed"


# --- I. Reports: UTF-8 byte-order mark only on the CSV download ------------------------------------

def test_csv_download_carries_a_utf8_bom_and_other_formats_do_not(client):
    """Requirement: the CSV download opens correctly in Excel (BOM) while JSON, Markdown and HTML stay BOM-free."""
    run_id = start_run(client, target="10.10.20.5", tools=["nmap", "whatweb", "nikto"]).json()["id"]
    wait_for_run(client, run_id)
    csv_report = client.get(f"/api/runs/{run_id}/report", params={"format": "csv"})
    assert csv_report.status_code == 200
    assert csv_report.content.startswith(UTF8_BOM) and csv_report.text.startswith(BOM_TEXT + "section,")
    for fmt in ("json", "md", "html"):
        other = client.get(f"/api/runs/{run_id}/report", params={"format": fmt})
        assert other.status_code == 200 and not other.content.startswith(UTF8_BOM), fmt


def test_render_csv_itself_has_no_bom():
    """Requirement: the BOM is added by the download endpoint only; the CSV renderer keeps producing plain text."""
    csv_text = render_csv(make_run(id="csvbom000001", target="10.10.20.5", tools=["nmap"]))
    assert csv_text.startswith("section,") and BOM_TEXT not in csv_text


# --- J. Static checks of the dashboard, launch scripts and README -----------------------------------

def test_phone_layout_clips_page_overflow_instead_of_hiding_it():
    """Requirement: on phones the page uses overflow-x: clip, so the sticky top bar keeps working."""
    css = (DASHBOARD / "styles.css").read_text(encoding="utf-8")
    match = re.search(r"@media \(max-width: 900px\) \{\n(.*?)\n\}", css, re.DOTALL)
    assert match, "the 900px media query is missing from dashboard/styles.css"
    assert "overflow-x: clip" in match.group(1) and "overflow-x: hidden" not in match.group(1)


def test_run_sh_checks_pip_through_the_venv_interpreter():
    """Requirement: run.sh decides whether .venv is usable by asking its interpreter for pip (python -m pip)."""
    text = (BASE_DIR / "run.sh").read_text(encoding="utf-8")
    condition = next((line for line in text.splitlines() if line.startswith('if [ ! -x ".venv/bin/python" ]')), "")
    assert condition, "the .venv condition is missing from run.sh"
    assert "-m pip --version" in condition


def test_run_ps1_checks_pip_with_find_spec_and_without_a_stderr_redirect():
    """Requirement: run.ps1 detects pip with importlib's find_spec and never redirects stderr with 2>$null."""
    text = (BASE_DIR / "run.ps1").read_text(encoding="utf-8", errors="replace")
    assert "find_spec('pip')" in text
    assert "2>$null" not in text


def test_readme_manual_start_uses_the_venv_interpreter():
    """Requirement: the README's manual start command runs uvicorn through the project's virtual environment, and
    the docs describe the settings validation, the rules-mode refinement and the auto provider's credentials as
    the code implements them."""
    text = (BASE_DIR / "README.md").read_text(encoding="utf-8")
    assert ".venv/bin/python -m uvicorn app.main:app" in text
    assert "control characters and quotes in values" not in text and "single quotes, `${`" in text
    assert "`ANTHROPIC_AUTH_TOKEN` or an `ant auth login` profile" in text
    guide = (BASE_DIR / "docs" / "TESTING_GUIDE.md").read_text(encoding="utf-8")
    assert "refinement is disabled" not in guide and "repeats the plan with a note" in guide
    example = (BASE_DIR / ".env.example").read_text(encoding="utf-8")
    assert "ANTHROPIC_AUTH_TOKEN" in example


def _fmt_dur_source() -> str:
    """The JavaScript source of the dashboard's fmtDur() helper, cut out of dashboard/app.js."""
    js = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    match = re.search(r"function fmtDur\(seconds\) \{\n(?:.*\n)*?  \}", js)
    assert match, "fmtDur() was not found in dashboard/app.js"
    return match.group(0)


def test_fmt_dur_rounds_once_before_splitting_into_units():
    """Requirement: fmtDur rounds the total seconds once, so 119.6 s can never become "1m 60s"."""
    assert "Math.round" in _fmt_dur_source()


def test_fmt_dur_boundary_values_evaluated_with_node(tmp_path):
    """Requirement: fmtDur(119.6) reads "2m 00s", fmtDur(3599.7) "1h 0m" and 59.97 s "1m 00s" (never "60.0s") when
    the real function runs."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed, so the JavaScript cannot be evaluated here")
    script = tmp_path / "fmtdur.js"
    script.write_text(_fmt_dur_source() + "\nconsole.log(JSON.stringify([fmtDur(119.6), fmtDur(3599.7), fmtDur(59.94), fmtDur(59.97)]));\n",
                      encoding="utf-8")
    proc = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == ["2m 00s", "1h 0m", "59.9s", "1m 00s"]
