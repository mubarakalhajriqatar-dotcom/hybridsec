"""Regression tests for the third review round (backend): one test per fix, so none of them can come back.

Each test names the behaviour it protects and its docstring states the requirement it checks. Like the rest of
the suite the tests run offline: no scanner is ever launched (the pipeline's run_command is replaced by fakes),
the planner is the rules engine, and every .env write goes to the private file tests/test_api.py sets up.
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest
from dotenv import dotenv_values
from fastapi.testclient import TestClient

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import hybrid, planner
from app.config import BASE_DIR, ENV_FILE, host_without_port, settings
from app.envfile import EnvValueError, update_env_file, validate_value
from app.main import _hostname, app
from app.routers.settings_api import require_local
from app.schemas import PortFinding, StageResult, VulnFinding, WebFinding
from app.tools import parsers, runner
from app.tools.registry import STAGE_ORDER, TOOLS
from app.tools.runner import CommandResult
from tests.test_api import make_run, run_stage_handler

# Safety net: every .env write below must go to the throwaway file that tests/test_api.py configured.
assert Path(os.environ["HYBRIDSEC_ENV_FILE"]) == ENV_FILE and ENV_FILE.name == "test.env"

OBJECTIVE = "Round-3 test: plan a hybrid scan of an authorized lab host."


# --- Fixtures and helpers -------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    # The TestClient's peer is "testclient", not a loopback IP, so the settings guard is overridden here.
    app.dependency_overrides[require_local] = lambda: None
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _fake_tools(monkeypatch, run_command) -> None:
    """Pretend every scanner is installed and route the pipeline's run_command to the given fake; name lookups
    answer IPv4 only so no host name reaches the real resolver."""
    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", run_command)
    monkeypatch.setattr(hybrid, "_address_families", lambda hostname: {socket.AF_INET})


def _whatweb(text: str) -> WebFinding:
    """Parse `text` as WhatWeb's JSON log for a probe of http://10.0.0.5."""
    return parsers.parse_whatweb_json(text, "http://10.0.0.5", "10.0.0.5", 80)


# --- A. Clickjacking: no other site may show the dashboard in a frame ------------------------------

@pytest.mark.parametrize("path", ["/", "/api/health", "/docs", "/favicon.ico"])
def test_every_response_forbids_framing_by_other_sites(client, path):
    """Requirement: a hidden frame on another site could trick the operator into clicking Delete or Clear key,
    so every response carries X-Frame-Options: DENY and a CSP frame-ancestors 'none'."""
    resp = client.get(path)
    assert resp.status_code == 200
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["content-security-policy"] == "frame-ancestors 'none'"


def test_framing_headers_are_added_next_to_the_existing_cache_rule(client, monkeypatch):
    """Requirement: the new headers join the dashboard's Cache-Control rule instead of replacing it, and they are
    on every response: the guards' 400 and 403 rejections, the liveness-only health answer under an unknown Host
    and the answer to a crash included."""
    resp = client.get("/")
    assert resp.headers["cache-control"] == "no-cache" and "text/html" in resp.headers["content-type"]
    framed = {"x-frame-options": "DENY", "content-security-policy": "frame-ancestors 'none'"}

    def headers_of(response) -> dict:
        return {name: response.headers.get(name) for name in framed}

    rejected = client.get("/api/tools", headers={"Host": "evil.example"})
    assert rejected.status_code == 400 and headers_of(rejected) == framed
    liveness = client.get("/api/health", headers={"Host": "evil.example"})
    assert liveness.json() == {"status": "ok"} and headers_of(liveness) == framed
    cross = client.post("/api/ai/plan", json={"tools": ["nmap"], "objective": OBJECTIVE},
                        headers={"Origin": "http://evil.example"})
    assert cross.status_code == 403 and headers_of(cross) == framed

    def crash(*args, **kwargs):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr("app.storage.list_runs", crash)
    with TestClient(app, base_url="http://localhost", raise_server_exceptions=False) as quiet:
        crashed = quiet.get("/api/runs")
        # A malformed IPv6 literal in the Origin or Host header is rejected by the guard, never a 500.
        for origin in ("http://[::1", "http://::1]", "http://[evil]", "http://[1.2.3.4]"):
            refused = quiet.post("/api/ai/plan", json={"tools": ["nmap"], "objective": OBJECTIVE},
                                 headers={"Origin": origin})
            assert refused.status_code == 403, origin
        for host in ("[::1", "[evil]:8000", "a://[::1"):  # the last one crashed the guard before the fix
            assert quiet.get("/api/tools", headers={"Host": host}).status_code == 400, host
        # A list field holding a thousand nested lists (a 2 KB body) is a 422 with the usual error list, never a 500:
        # FastAPI echoes the rejected value in each error, and encoding that echo passed Python's recursion limit.
        nested = "[" * 1000 + "]" * 1000
        execute = f'{{"target": "127.0.0.1", "authorized": true, "simulate": true, "tools": {nested}}}'
        for method, path, field, body in (
                ("POST", "/api/hybridizations/execute", "tools", execute),
                ("POST", "/hybridizations/execute", "tools", execute),
                ("POST", "/api/ai/plan", "tools", f'{{"objective": {json.dumps(OBJECTIVE)}, "tools": {nested}}}'),
                ("POST", "/api/tools/custom", "args", f'{{"name": "r3deep", "program": "curl", "args": {nested}}}'),
                ("PUT", "/api/settings", "allowed_targets", f'{{"allowed_targets": {nested}}}')):
            deep = quiet.request(method, path, content=body, headers={"Content-Type": "application/json"})
            assert deep.status_code == 422 and headers_of(deep) == framed, path
            error = deep.json()["detail"][0]
            assert error["loc"] == ["body", field, 0] and error["type"] == "string_type" and "input" not in error, path
    assert crashed.status_code == 500 and headers_of(crashed) == framed
    assert client.get("/favicon.ico").headers["cache-control"] == "public, max-age=86400"


# --- B. .env writer: values python-dotenv would not read back ---------------------------------------

@pytest.mark.parametrize("bad", ["claude-x\\", "a\\\\b", "x${HOME}"],
                         ids=["trailing-backslash", "doubled-backslash", "interpolation"])
def test_validate_value_refuses_values_python_dotenv_would_misread(bad):
    """Requirement: a value that ends in a backslash, holds two backslashes in a row or holds ${ is refused with
    the setting's name, because python-dotenv decodes escapes and expands ${NAME} inside single quotes."""
    with pytest.raises(EnvValueError, match="ANTHROPIC_MODEL must not"):
        validate_value(bad, "ANTHROPIC_MODEL")


def test_validate_value_still_accepts_a_lone_backslash_and_a_bare_dollar():
    """Requirement: the new checks are narrow; a lone backslash inside a value and a bare $ stay storable."""
    for value in ("back\\slash", "a\\nb", "$HOME", "pa$$word"):
        assert validate_value(value) == value


def test_env_file_writer_refuses_a_trailing_backslash_before_touching_the_file(tmp_path):
    """Requirement: the save is refused up front, so the allow-list below the damaged value is never lost.

    Before the fix the trailing backslash hid the closing quote, python-dotenv swallowed every line up to the
    next apostrophe, and the allow-list came back empty, which the scope check treats as allow-everything.
    """
    env = tmp_path / "lab.env"
    env.write_text("OPENAI_BASE_URL=https://api.openai.com/v1\nHYBRIDSEC_ALLOWED_TARGETS=10.10.20.0/24\n"
                   "# lab rule: don't widen the scope without the instructor\n", encoding="utf-8")
    before = env.read_text(encoding="utf-8")
    with pytest.raises(EnvValueError, match="OPENAI_BASE_URL must not end with a backslash"):
        update_env_file(env, {"OPENAI_BASE_URL": "https://llm.lab.example.edu/v1\\"})
    assert env.read_text(encoding="utf-8") == before
    assert dotenv_values(env)["HYBRIDSEC_ALLOWED_TARGETS"] == "10.10.20.0/24"


def test_settings_api_refuses_a_base_url_ending_in_a_backslash(client):
    """Requirement: PUT /api/settings answers 400 for such a value and the configuration is unchanged."""
    before = client.get("/api/settings").json()
    resp = client.put("/api/settings", json={"openai_base_url": "https://llm.lab.example.edu/v1\\"})
    assert resp.status_code == 400
    assert "OpenAI base URL must not end with a backslash" in resp.json()["detail"]
    after = client.get("/api/settings").json()
    assert (after["openai_base_url"], after["allowed_targets"]) == (before["openai_base_url"],
                                                                     before["allowed_targets"])


# --- C. Hostile scanner output: size caps ----------------------------------------------------------

def test_whatweb_page_title_is_capped_like_technology_strings():
    """Requirement: a multi-megabyte <title> served by the target is stored as at most 300 characters (technology
    strings were already cut at 200); an ordinary title is kept as it is."""
    assert len(_whatweb(json.dumps([{"plugins": {"Title": {"string": ["T" * 5000]}}}])).title) == 300
    assert _whatweb(json.dumps([{"plugins": {"Title": {"string": ["Lab portal"]}}}])).title == "Lab portal"


def test_report_files_are_read_with_the_same_cap_as_stdout(tmp_path, monkeypatch):
    """Requirement: the WhatWeb and Nikto report files fall under MAX_OUTPUT_CHARS like stdout and stderr, and
    the file is still deleted after it was read."""
    assert hybrid.MAX_OUTPUT_CHARS == runner.MAX_OUTPUT_CHARS
    monkeypatch.setattr(hybrid, "MAX_OUTPUT_CHARS", 10)
    report = tmp_path / "whatweb.json"
    report.write_text("x" * 50, encoding="utf-8")
    assert hybrid._read_and_remove(str(report)) == "x" * 10
    assert not report.exists()


# --- D. Readability fixes whose documented behaviour is now pinned ----------------------------------

def test_nikto_subprocess_timeout_is_maxtime_plus_five_seconds(monkeypatch):
    """Nikto stops itself at -maxtime; the subprocess timeout adds 5 seconds so it can still write its report."""
    seen = []

    def nikto(command, timeout):
        seen.append((command[command.index("-maxtime") + 1], timeout))
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    _fake_tools(monkeypatch, nikto)
    run = make_run(id="r3nikto00001", target="10.0.0.5", status="running", tools=["nikto"],
                   stages=[StageResult(stage="web_vuln_scan", tool="nikto")])
    run_stage_handler(hybrid.stage_web_vuln_scan, run,
                      {"web_ports": [PortFinding(host="10.0.0.5", port=80, service="http", is_web=True)]})
    assert seen == [("30s", 35.0)]


def test_highlights_list_findings_then_risky_services_then_versions():
    """The order _highlights() documents: severe findings, then exposed services, then disclosed versions."""
    run = make_run(ports=[PortFinding(host="10.10.20.5", port=21, service="ftp")],
                   web=[WebFinding(url="http://10.10.20.5", host="10.10.20.5", port=80, status_code=200,
                                   technologies=[{"name": "nginx", "version": "1.18.0"}])],
                   vulns=[VulnFinding(url="http://10.10.20.5", severity="medium", description="M")])
    assert hybrid.summarize(run).highlights == ["[medium] M",
                                                "Management or database service exposed: ftp on port 21",
                                                "nginx 1.18.0 disclosed at http://10.10.20.5"]


def test_settings_are_reloaded_once_per_request(client, monkeypatch):
    """guard_requests() is the one place that re-reads .env for a request; the handlers rely on it. The only
    other reload is _settings_view(), so that the answer to a PUT shows the values it has just written."""
    calls = []
    real_reload = settings.reload
    monkeypatch.setattr(settings, "reload", lambda: calls.append(1) or real_reload())
    plan = client.post("/api/ai/plan", json={"tools": ["nmap", "whatweb"], "objective": OBJECTIVE})
    assert plan.status_code == 200, plan.text
    assert client.get("/api/health").status_code == 200
    assert len(calls) == 2
    calls.clear()
    assert client.put("/api/settings", json={"allow_simulation": True}).status_code == 200
    assert len(calls) == 2
    calls.clear()
    assert client.get("/api/tools/custom").status_code == 200  # the custom-tool listing re-reads nothing either
    assert len(calls) == 1


@pytest.mark.parametrize("raw,expected", [
    ("localhost:8000", "localhost"),
    ("[::1]:8000", "::1"),
    ("::1", "::1"),
    ("[::1", "[::1"),
    ("", ""),
    ("  LocalHost ", "localhost"),
], ids=["port", "ipv6-port", "bare-ipv6", "unbalanced", "empty", "case"])
def test_allow_list_and_request_guard_reduce_host_names_the_same_way(raw, expected):
    """One helper serves both: the Host allow-list in config.py and the Host/Origin guard in main.py must agree."""
    assert host_without_port(raw) == expected
    assert _hostname(raw) == expected


def test_hostname_guard_still_accepts_a_full_url(monkeypatch):
    """An Origin header is a full URL, and so may be an HYBRIDSEC_ALLOWED_HOSTS entry: both name their host, so an
    entry written as http://hybridsec.lab:8000/ trusts hybridsec.lab and not the scheme "http"."""
    assert _hostname("http://Example.COM:80/x") == "example.com"
    assert _hostname("https://[::1]:8000") == "::1"
    assert host_without_port("http://HybridSec.lab:8000/") == "hybridsec.lab"
    assert host_without_port("https://[::1]:8000/x") == "::1"
    # An IPv6 address matches however it is written: every spelling reduces to the canonical form browsers send.
    assert host_without_port("[2001:0db8::0001]:8000") == host_without_port("2001:db8:0:0:0:0:0:1") == "2001:db8::1"
    monkeypatch.setenv("HYBRIDSEC_ALLOWED_HOSTS", "http://hybridsec.lab:8000/, lab2.example, 2001:0db8::0001")
    try:
        settings.reload()
        assert {"hybridsec.lab", "lab2.example"} <= settings.allowed_hosts and "http" not in settings.allowed_hosts
        assert TestClient(app, base_url="http://[2001:db8::1]:8000").get("/api/tools").status_code == 200
        # A wildcard bind address spelled out in full is still a wildcard, never a trusted name.
        monkeypatch.setenv("HYBRIDSEC_HOST", "0:0:0:0:0:0:0:0")
        settings.reload()
        assert "::" not in settings.allowed_hosts
    finally:
        monkeypatch.delenv("HYBRIDSEC_ALLOWED_HOSTS")
        monkeypatch.delenv("HYBRIDSEC_HOST", raising=False)
        settings.reload()


def test_plan_schema_and_rules_planner_take_stage_names_from_the_registry():
    """The planner cannot drift from the tool registry: the schema's stage enum is STAGE_ORDER, the step templates
    carry no stage of their own, and every rules-plan step gets its tool's registry stage."""
    stage_property = planner.PLAN_SCHEMA["properties"]["workflow"]["items"]["properties"]["stage"]
    assert stage_property["enum"] == STAGE_ORDER
    assert all("stage" not in entry for entry in planner._STEP_LIBRARY.values())
    plan = planner.rules_plan(planner.PlanRequest(tools=["nikto", "nmap", "whatweb"], objective=OBJECTIVE))
    assert [(s.tool, s.stage) for s in plan.workflow] == [(t, TOOLS[t].stage) for t in ("nmap", "whatweb", "nikto")]


def test_architecture_guide_sends_new_stage_handlers_through_start_tool():
    """docs/ARCHITECTURE.md must match the code: stage handlers run tools with _start_tool(), never run_command()
    directly, because _start_tool() turns a process that cannot start into a failed result."""
    text = (BASE_DIR / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "run it with `_start_tool()` (not `run_command()`" in text
    assert "call `run_command()`" not in text
    assert "runs Nmap through `_run_nmap()` and `_start_tool()`" in text
