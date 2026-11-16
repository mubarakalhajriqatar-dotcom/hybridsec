"""Tests for tool profiles: the preset, non-exploitative option sets a run may pick per tool (Zenmap-style "profiles").

They cover the catalogue in app/tools/registry.py, the profile fields of GET /api/tools, the validation of
ExecuteRequest.profiles, the profile recorded on every run, the live command lines each profile produces, the
simulated results, the parser's NSE script notes, runs stored before profiles existed, the reports, the comparison
note and the dashboard's static markup. Like the rest of the suite they run offline: every scanner is a fake that
records its command line, the resolver is replaced, and importing tests.test_api first points the app at a private
.env file and a temporary data directory.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import socket
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import hybrid, storage
from app.compare import compare_runs
from app.config import BASE_DIR, settings
from app.hybrid import RunManager, simulate_ports, simulate_vulns
from app.main import app
from app.planner import EXECUTOR_COMMANDS
from app.reports import render_csv, render_html, render_markdown, tools_with_profiles
from app.routers import hybrid as hybrid_router
from app.routers.settings_api import peer_is_local, require_local
from app.schemas import (
    CustomTool,
    ExecuteRequest,
    PortFinding,
    Run,
    RunSummary,
    StageResult,
    ToolProfileInfo,
    VulnFinding,
    WebFinding,
)
from app.tools import parsers
from app.tools.registry import TOOLS, ToolProfile, default_profile, find_profile, profile_for_run, profile_label
from app.tools.runner import CommandResult
from tests.test_api import CUSTOM_BODY, make_run, new_plan, run_stage_handler, start_run, wait_for_run

DASHBOARD = BASE_DIR / "dashboard"

# The documented catalogue: (key, flags) per tool in order; the first entry is the default and reproduces the
# command line the pipeline ran before profiles existed.
CATALOGUE = {
    "nmap": [("version", "-sV -Pn -T4"), ("quick", "-Pn -T4"), ("scripts", "-sV -sC -Pn -T4"), ("polite", "-sV -Pn -T2")],
    "whatweb": [("stealthy", "-a 1"), ("aggressive", "-a 3"), ("heavy", "-a 4")],
    "nikto": [("all", ""), ("files", "-Tuning 123"), ("software", "-Tuning be"), ("injection", "-Tuning 49c")],
}
DEFAULT_KEYS = {"nmap": "version", "whatweb": "stealthy", "nikto": "all"}
HISTORICAL_ARGS = {"nmap": ("-sV", "-Pn", "-T4"), "whatweb": ("-a", "1"), "nikto": ()}
EVERY_PROFILE = [(tool, profile) for tool in TOOLS for profile in TOOLS[tool].profiles]
# Options no profile may carry: UDP or full-port sweeps, OS detection, aggressive mode, insane timing, rate flooding
# and Nikto's mutation/evasion techniques. NSE script selection is checked by prefix below.
INTRUSIVE_OPTIONS = {"-sU", "-O", "-A", "-p-", "-T5", "--min-rate", "--max-rate", "-mutate", "-evasion", "-e", "-Plugins"}

NMAP_HEAD = '<?xml version="1.0"?><nmaprun scanner="nmap">'
HTTP_HOST_XML = NMAP_HEAD + (
    '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/><ports>'
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>'
    "</ports></host></nmaprun>"
)
IPV6_HOST_XML = NMAP_HEAD + (
    '<host><status state="up"/><address addr="2001:db8::5" addrtype="ipv6"/><ports>'
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
)
SCRIPTED_HOST_XML = NMAP_HEAD + (
    '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/><ports>'
    '<port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu Linux; protocol 2.0"/>'
    '<script id="ssh-hostkey" output="&#10;  3072 SHA256:aaaa (RSA)&#10;  256 SHA256:bbbb (ECDSA)&#10;"/>'
    '<script id="banner" output="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"/>'
    "</port>"
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/>'
    '<script id="http-title" output="Demo Portal"/>'
    "</port>"
    '<port protocol="tcp" portid="3306"><state state="open"/>'
    '<service name="mysql" product="MySQL" version="8.0.36" extrainfo="unauthorized"/></port>'
    '<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp"/>'
    '<script id="smtp-commands" output="never reported: the port is not open"/></port>'
    "</ports></host></nmaprun>"
)
# The two untuned Nikto header checks that simulate_vulns() reports for every web service, in order.
HEADER_FINDINGS = ["The anti-clickjacking X-Frame-Options header is not present.",
                   "The X-Content-Type-Options header is not set. User agents may MIME-sniff content."]
PROFILE_NOTE = ("The runs used different profiles for nmap (Service and version detection vs Quick port scan), so some "
                "differences may come from the profile rather than from the target.")


# --- Fixtures and helpers -------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def database_tables():
    """Runs are saved to SQLite; the app's startup normally creates the tables, so create them here."""
    storage.init_db()


@pytest.fixture(scope="module")
def client():
    """One API client for the module. Its peer is "testclient", so the loopback-only guards are overridden."""
    app.dependency_overrides[require_local] = lambda: None
    app.dependency_overrides[peer_is_local] = lambda: True
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _report_path(command: list[str]) -> str:
    """The report file a fake WhatWeb or Nikto call must write, taken from the command line."""
    for index, part in enumerate(command):
        if part.startswith("--log-json="):
            return part.split("=", 1)[1]
        if part == "-output":
            return command[index + 1]
    raise AssertionError(f"no report file in {command}")


def masked(command: list[str]) -> list[str]:
    """A WhatWeb or Nikto command line with its temporary report file shown as <file>, as the stage records it."""
    path = _report_path(command)
    return [part.replace(path, "<file>") for part in command]


def capture_commands(monkeypatch, nmap_xml: str = HTTP_HOST_XML) -> list[list[str]]:
    """Pretend the scanners are installed and record every command line the pipeline starts.

    Nothing is executed and name lookups answer IPv4 only, so no scanner and no resolver is touched. The fake
    Nmap answers `nmap_xml`, the fake WhatWeb writes a report that marks its URL reachable (so Nikto has
    something to scan) and the fake Nikto writes one finding.
    """
    commands: list[list[str]] = []

    def fake(command, timeout):
        commands.append(list(command))
        tool = os.path.basename(command[0])
        stdout = nmap_xml if tool == "nmap" else ""
        if tool == "whatweb":
            report = [{"target": command[-1], "http_status": 200, "plugins": {"HTTPServer": {"string": ["nginx"]}}}]
            Path(_report_path(command)).write_text(json.dumps(report), encoding="utf-8")
        elif tool == "nikto":
            report = [{"host": "10.10.20.5", "vulnerabilities": [{"msg": HEADER_FINDINGS[0], "url": "/"}]}]
            Path(_report_path(command)).write_text(json.dumps(report), encoding="utf-8")
        return CommandResult(command=command, exit_code=0, stdout=stdout, stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", fake)
    monkeypatch.setattr(hybrid, "_address_families", lambda hostname: {socket.AF_INET})
    return commands


def live_run(run_id: str, target: str = "10.10.20.5", tools: tuple[str, ...] = ("nmap",),
             profiles: dict[str, str] | None = None) -> Run:
    """A running live-mode Run with one pending stage per tool, whose recorded profiles are `profiles` ({} when
    None: a run saved before profiles existed)."""
    return make_run(id=run_id, target=target, status="running", tools=list(tools), profiles=profiles or {},
                    stages=[StageResult(stage=TOOLS[tool].stage, tool=tool) for tool in tools])


def web_context() -> dict:
    """A stage context with one web service to probe and plenty of time left."""
    return {"web_ports": [PortFinding(host="10.10.20.5", port=80, service="http", product="nginx", is_web=True)],
            "deadline": time.monotonic() + 100}


def top_ports() -> str:
    """The port count a request without top_ports asks Nmap for (the default, capped by the server maximum)."""
    return str(min(100, settings.max_top_ports))


def execute_and_wait(request: ExecuteRequest, tools: list[str], profiles: dict[str, str] | None = None,
                     budget: int = 60) -> Run:
    """Run the whole pipeline on a fresh RunManager and return the stored final state."""
    manager = RunManager()
    run = manager.create(request, request.target, tools, None, budget, profiles)
    deadline = time.monotonic() + 10
    while manager.is_active(run.id) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not manager.is_active(run.id), "the run did not finish in time"
    return storage.get_run(run.id)


def simulated_port(predicate) -> PortFinding:
    """The first simulated port, over a range of lab addresses, that satisfies `predicate`. The simulation is a
    deterministic function of the target, so the candidates are searched instead of hard-coding an address."""
    for n in range(1, 80):
        for port in simulate_ports(f"10.10.30.{n}")[0]:
            if predicate(port):
                return port
    raise AssertionError("no candidate target simulates such a port")


def completed_run(run_id: str, tools: list[str], profiles: dict[str, str], **fields) -> Run:
    """A completed Run on a lab address with the given tools and recorded profiles."""
    stages = [StageResult(stage=TOOLS[tool].stage, tool=tool, status="completed") for tool in tools]
    return make_run(id=run_id, target="10.10.20.5", tools=tools, profiles=profiles, stages=stages, **fields)


def _port_xml(scripts: str) -> str:
    """An Nmap report with one open port (443, no extrainfo) that carries the given <script> elements."""
    return (NMAP_HEAD + '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/>'
            + scripts + "</port></ports></host></nmaprun>")


def _css() -> str:
    return (DASHBOARD / "styles.css").read_text(encoding="utf-8")


def _js() -> str:
    return (DASHBOARD / "app.js").read_text(encoding="utf-8")


def _rule(css: str, selector_pattern: str) -> str:
    """The declarations of the one single-line rule whose selector matches `selector_pattern` at a line start."""
    match = re.search(r"^" + selector_pattern + r" \{([^}]*)\}", css, re.MULTILINE)
    assert match, f"no rule for {selector_pattern!r} in dashboard/styles.css"
    return match.group(1)


# --- A. The catalogue -----------------------------------------------------------------------------

@pytest.mark.parametrize("tool", list(TOOLS))
def test_every_tool_offers_the_documented_profiles_in_order(tool):
    """Every tool has at least one profile and the catalogue is exactly the documented one, in order: keys are
    unique, lower-case and trimmed, label and description are non-empty, and `flags` is the arguments joined
    by single spaces (each argument is one token, so the flags split back into the arguments)."""
    profiles = TOOLS[tool].profiles
    assert len(profiles) >= 1
    assert [(p.key, p.flags) for p in profiles] == CATALOGUE[tool]
    keys = [p.key for p in profiles]
    assert len(set(keys)) == len(keys)
    for profile in profiles:
        assert profile.key and profile.key == profile.key.strip().lower()
        assert profile.label.strip() and profile.description.strip()
        assert all(arg.split() == [arg] for arg in profile.args)
        assert profile.flags == " ".join(profile.args) and profile.flags.split() == list(profile.args)


@pytest.mark.parametrize("tool", list(TOOLS))
def test_default_profile_is_first_and_reproduces_the_historical_flags(tool):
    """The first profile is the default, its arguments are the flags the pipeline used before profiles existed,
    and the planner's command templates (what an approved plan promises) still show those flags."""
    default = default_profile(tool)
    assert default is TOOLS[tool].profiles[0] and default.key == DEFAULT_KEYS[tool]
    assert default.args == HISTORICAL_ARGS[tool]
    assert not default.flags or f" {default.flags} " in f" {EXECUTOR_COMMANDS[tool]} "


@pytest.mark.parametrize("tool,profile", EVERY_PROFILE, ids=[f"{tool}-{p.key}" for tool, p in EVERY_PROFILE])
def test_no_profile_carries_an_intrusive_or_noisy_option(tool, profile):
    """Profiles decide how a tool examines the target, never whether it attacks it: no NSE script selection
    (--script=brute, ...), no UDP or full-port sweeps, no OS detection, no insane timing, no evasion, and no
    Nikto denial-of-service tuning (category 6). Every Nmap profile keeps -Pn, as the registry promises."""
    args = profile.args
    assert not INTRUSIVE_OPTIONS & set(args)
    assert not any(arg.startswith("--script") for arg in args)
    assert not any(word in arg.lower() for arg in args for word in ("brute", "exploit", "fuzz", "attack"))
    if tool == "nmap":
        assert "-Pn" in args
        assert all(arg in {"-T2", "-T3", "-T4"} for arg in args if re.fullmatch(r"-T\d", arg))
    if tool == "whatweb" and "-a" in args:
        assert args[args.index("-a") + 1] in {"1", "2", "3", "4"}
    if tool == "nikto" and "-Tuning" in args:
        tuning = args[args.index("-Tuning") + 1]
        assert tuning and set(tuning) <= set("012345789abcdex")  # every Nikto category except 6 (DoS)


@pytest.mark.parametrize("key,expected", [
    ("quick", "quick"), ("QUICK", "quick"), ("  Quick ", "quick"),
    (None, "version"), ("", "version"), ("   ", "version"),
    ("turbo", None), ("quick scan", None), ("-Pn -T4", None),
], ids=["exact", "upper", "spaced", "none", "empty", "blank", "unknown", "two-words", "flags-not-key"])
def test_find_profile_normalises_the_key_and_defaults_when_it_is_blank(key, expected):
    """find_profile() ignores letter case and surrounding spaces, treats None or a blank key as the default, and
    answers None (never a guess) for a key the tool does not offer."""
    profile = find_profile("nmap", key)
    assert (profile.key if profile else None) == expected


def test_profile_for_run_and_profile_label_fall_back_sensibly():
    """profile_for_run() applies the recorded profile and falls back to the default when the run recorded nothing
    (None or {}), nothing for that tool, or a key no longer in the catalogue. profile_label() is the drop-down
    text of a profile; an unknown key is shown as stored, an unknown tool gets its key back, no key means the
    default's label, and a profile without arguments has empty flags."""
    assert profile_for_run("nmap", {"nmap": "quick"}).key == "quick"
    assert profile_for_run("whatweb", {"whatweb": " HEAVY "}).key == "heavy"
    assert profile_for_run("nmap", None).key == "version"
    assert profile_for_run("nmap", {}).key == "version"
    assert profile_for_run("nmap", {"whatweb": "heavy"}).key == "version"
    assert profile_for_run("nikto", {"nikto": "renamed-away"}).key == "all"
    assert profile_label("nmap", "quick") == "Quick port scan"
    assert profile_label("whatweb", " Stealthy ") == "Stealthy, level 1"
    assert profile_label("nikto", "all") == "All checks"
    assert profile_label("nmap", None) == "Service and version detection"
    assert profile_label("nmap", "legacy") == "legacy"
    assert profile_label("masscan", "fast") == "fast" and profile_label("masscan", None) == ""
    assert ToolProfile("x", "X", "x", ()).flags == "" and ToolProfile("y", "Y", "y", ("-a", "1")).flags == "-a 1"


# --- B. GET /api/tools ----------------------------------------------------------------------------

def test_api_tools_lists_each_tools_profiles_default_first(client):
    """GET /api/tools carries every tool's profiles as {key, label, description, flags, default} in catalogue
    order, with the default first and exactly one default per tool."""
    tools = {entry["name"]: entry for entry in client.get("/api/tools").json()}
    assert set(tools) == set(TOOLS)
    for name, spec in TOOLS.items():
        listed = tools[name]["profiles"]
        assert [set(p) for p in listed] == [set(ToolProfileInfo.model_fields)] * len(spec.profiles)
        assert [(p["key"], p["label"], p["description"], p["flags"]) for p in listed] == [
            (p.key, p.label, p.description, p.flags) for p in spec.profiles]
        assert [p["default"] for p in listed] == [True] + [False] * (len(listed) - 1)
        assert listed[0]["key"] == DEFAULT_KEYS[name] == default_profile(name).key


# --- C. Execute request validation ----------------------------------------------------------------

def test_execute_rejects_a_profile_for_an_unknown_tool(client):
    """A profile for a tool HybridSec does not know is refused with 400 and the list of supported tools."""
    resp = start_run(client, profiles={"masscan": "quick"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Unknown tool in profiles: masscan. Supported: nmap, whatweb, nikto."
    # A registered custom tool is known, but it has no profiles.
    assert client.post("/api/tools/custom", json=CUSTOM_BODY).status_code == 201
    try:
        resp = start_run(client, tools=["nmap", "pytestcheck"], profiles={"pytestcheck": "x"})
        assert resp.status_code == 400 and resp.json()["detail"] == "pytestcheck is a custom tool and has no profiles."
    finally:
        storage.delete_custom_tool("pytestcheck")


def test_execute_rejects_a_profile_for_a_tool_that_is_not_part_of_the_run(client):
    """A profile may only be given for a tool the run executes; the message names the run's tools."""
    resp = start_run(client, tools=["nmap"], profiles={"nikto": "files"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "A profile was given for nikto, which is not part of this run (nmap)."
    resp = start_run(client, profiles={"Nikto": "files"})  # the default tool pair; the name is normalised first
    assert resp.status_code == 400
    assert resp.json()["detail"] == "A profile was given for nikto, which is not part of this run (nmap, whatweb)."


@pytest.mark.parametrize("tool,offered", [
    ("nmap", "version, quick, scripts, polite"),
    ("whatweb", "stealthy, aggressive, heavy"),
    ("nikto", "all, files, software, injection"),
])
def test_execute_rejects_an_unknown_profile_key_and_lists_the_choices(client, tool, offered):
    """A typo in a profile key is reported with the keys the tool offers instead of silently running the default."""
    resp = start_run(client, tools=["nmap", "whatweb", "nikto"], profiles={tool: "turbo"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == f"Unknown {tool} profile: turbo. Choose one of: {offered}."


def test_execute_normalises_names_and_keys_and_refuses_malformed_profiles(client):
    """Tool names and keys are accepted in any letter case with surrounding spaces and recorded in canonical form,
    a blank key means the default (like leaving the tool out), and a value that is not a string map is a
    validation error (422), so a malformed request never starts a run."""
    resp = start_run(client, profiles={" NMAP ": "Quick", "WhatWeb": " HEAVY "})
    assert resp.status_code == 202, resp.text
    assert resp.json()["profiles"] == {"nmap": "quick", "whatweb": "heavy"}
    assert wait_for_run(client, resp.json()["id"])["profiles"] == {"nmap": "quick", "whatweb": "heavy"}
    resp = start_run(client, tools=["nmap"], profiles={"nmap": "   "})
    assert resp.status_code == 202, resp.text
    assert wait_for_run(client, resp.json()["id"])["profiles"] == {"nmap": "version"}
    assert start_run(client, profiles={"nmap": ["quick"]}).status_code == 422
    assert start_run(client, profiles="quick").status_code == 422
    assert start_run(client, profiles=["nmap"]).status_code == 422


def test_profile_errors_are_raised_before_anything_starts(client, monkeypatch):
    """Profiles are checked after the tool selection and before the installed-tool check and the run's creation:
    an unknown tool wins over a bad profile, and a bad profile on a live request is reported as such, without
    a run ever being created."""
    assert hybrid_router.manager is hybrid.manager
    monkeypatch.setattr(RunManager, "create", lambda self, *args, **kwargs: pytest.fail("a run was created"))
    resp = start_run(client, tools=["nikt0"], profiles={"masscan": "x"})
    assert resp.status_code == 400 and resp.json()["detail"].startswith("Unknown tool(s): nikt0.")
    resp = start_run(client, simulate=False, profiles={"nmap": "turbo"})
    assert resp.status_code == 400 and resp.json()["detail"].startswith("Unknown nmap profile: turbo.")


def test_profiles_are_accepted_with_a_plan_run_and_recorded(client):
    """A plan decides which tools run, not how: a planned run may choose profiles, they are recorded next to the
    plan id, and a profile for a planned tool the operator left out of the run is still refused."""
    plan = new_plan(client, ["nmap", "whatweb"], "Profile test: port scan then fingerprint of a lab host.")
    resp = start_run(client, plan_id=plan["id"], profiles={"whatweb": "aggressive"})
    assert resp.status_code == 202, resp.text
    run = wait_for_run(client, resp.json()["id"])
    assert run["plan_id"] == plan["id"] and run["tools"] == ["nmap", "whatweb"]
    assert run["profiles"] == {"nmap": "version", "whatweb": "aggressive"}
    denied = start_run(client, plan_id=plan["id"], tools=["nmap"], profiles={"whatweb": "aggressive"})
    assert denied.status_code == 400
    assert denied.json()["detail"] == "A profile was given for whatweb, which is not part of this run (nmap)."


# --- D. The profiles recorded on a run ------------------------------------------------------------

def test_every_run_records_the_effective_profile_of_each_tool(client):
    """A run records a profile key for every one of its tools, defaults filled in, from the moment it is queued:
    in the 202 answer, in GET /api/runs/{id}, in the GET /api/runs history and in its first log line."""
    resp = start_run(client, tools=["nmap", "whatweb", "nikto"], profiles={"nmap": "polite"})
    assert resp.status_code == 202, resp.text
    queued = resp.json()
    expected = {"nmap": "polite", "whatweb": "stealthy", "nikto": "all"}
    assert queued["profiles"] == expected
    assert queued["log"][0].endswith("profiles nmap=polite, whatweb=stealthy, nikto=all)")
    run = wait_for_run(client, queued["id"])
    assert run["profiles"] == expected and run["log"][0] == queued["log"][0]
    listed = next(item for item in client.get("/api/runs").json() if item["id"] == run["id"])
    assert listed["profiles"] == expected
    plain = wait_for_run(client, start_run(client).json()["id"])
    assert plain["profiles"] == {"nmap": "version", "whatweb": "stealthy"}
    assert plain["log"][0].endswith("profiles nmap=version, whatweb=stealthy)")


def test_run_manager_fills_defaults_for_missing_and_unknown_profiles():
    """RunManager.create() records the default for a tool without a choice and for a key it does not know (the
    router rejects such keys, but a stored choice can outlive a renamed profile), and logs the result."""
    request = ExecuteRequest(target="10.10.30.3", authorized=True, simulate=True)
    run = execute_and_wait(request, ["nmap", "whatweb"], {"nmap": "renamed-away", "whatweb": "heavy"})
    try:
        assert run.status == "completed"
        assert run.profiles == {"nmap": "version", "whatweb": "heavy"}
        assert run.log[0].endswith("profiles nmap=version, whatweb=heavy)")
    finally:
        storage.delete_run(run.id)
    run = execute_and_wait(request, ["nmap"])
    try:
        assert run.profiles == {"nmap": "version"} and run.log[0].endswith("profiles nmap=version)")
    finally:
        storage.delete_run(run.id)


# --- E. Live command lines ------------------------------------------------------------------------

def test_default_profiles_reproduce_the_historical_command_lines(monkeypatch):
    """With no profile recorded (a run from before profiles existed) the three command lines are, byte for byte,
    the ones the pipeline ran before: the defaults add nothing and move nothing."""
    commands = capture_commands(monkeypatch)
    run = live_run("tprofcmd0001", tools=("nmap", "whatweb", "nikto"))
    context: dict = {"deadline": time.monotonic() + 100}
    nmap_stage = run_stage_handler(hybrid.stage_port_scan, run, context)
    whatweb_stage = run_stage_handler(hybrid.stage_web_fingerprint, run, context, stage_index=1)
    nikto_stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, context, stage_index=2)
    assert [s.status for s in (nmap_stage, whatweb_stage, nikto_stage)] == ["completed"] * 3
    assert commands[0] == ["/fake/bin/nmap", "-sV", "-Pn", "-T4", "--open", "--top-ports", top_ports(),
                           "--host-timeout", "24s", "-oX", "-", "10.10.20.5"]
    assert masked(commands[1]) == ["/fake/bin/whatweb", "--color=never", "-a", "1", "--follow-redirect=same-site",
                                   "--log-json=<file>", "http://10.10.20.5"]
    assert masked(commands[2]) == ["/fake/bin/nikto", "-h", "http://10.10.20.5", "-Format", "json", "-output", "<file>",
                                   "-maxtime", "30s", "-nointeractive", "-ask", "no"]
    assert nmap_stage.command == " ".join(commands[0])
    assert whatweb_stage.command == " ".join(masked(commands[1]))
    assert nikto_stage.command == " ".join(masked(commands[2]))


@pytest.mark.parametrize("key", [p.key for p in TOOLS["nmap"].profiles])
def test_nmap_profile_arguments_lead_the_live_command_line(monkeypatch, key):
    """The Nmap profile's arguments come right after the executable; --open, the port count, the host timeout,
    the XML output and the target are added by the pipeline for every profile."""
    commands = capture_commands(monkeypatch)
    run = live_run(f"tprofnmap-{key}", profiles={"nmap": key})
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    args = list(find_profile("nmap", key).args)
    assert stage.status == "completed" and [p.port for p in run.ports] == [80]
    assert commands == [["/fake/bin/nmap", *args, "--open", "--top-ports", top_ports(), "--host-timeout", "24s",
                         "-oX", "-", "10.10.20.5"]]
    assert stage.command == " ".join(commands[0])


@pytest.mark.parametrize("key", [p.key for p in TOOLS["whatweb"].profiles])
def test_whatweb_profile_arguments_sit_between_the_colour_and_redirect_options(monkeypatch, key):
    """The WhatWeb profile's aggression level follows --color=never; same-site redirects, the JSON log and the
    URL are added by the pipeline for every profile."""
    commands = capture_commands(monkeypatch)
    run = live_run(f"tprofwhatweb-{key}", tools=("nmap", "whatweb"), profiles={"whatweb": key})
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, web_context(), stage_index=1)
    args = list(find_profile("whatweb", key).args)
    assert stage.status == "completed" and [w.reachable for w in run.web] == [True]
    assert [masked(c) for c in commands] == [["/fake/bin/whatweb", "--color=never", *args, "--follow-redirect=same-site",
                                              "--log-json=<file>", "http://10.10.20.5"]]
    assert stage.command == " ".join(masked(commands[0]))


@pytest.mark.parametrize("key", [p.key for p in TOOLS["nikto"].profiles])
def test_nikto_profile_arguments_follow_the_url(monkeypatch, key):
    """The Nikto profile's tuning (none for the complete scan) follows -h <url>; the JSON report, the time limit
    and the non-interactive options are added by the pipeline for every profile."""
    commands = capture_commands(monkeypatch)
    run = live_run(f"tprofnikto-{key}", tools=("nmap", "nikto"), profiles={"nikto": key})
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, web_context(), stage_index=1)
    args = list(find_profile("nikto", key).args)
    assert stage.status == "completed" and len(run.vulns) == 1
    assert [masked(c) for c in commands] == [["/fake/bin/nikto", "-h", "http://10.10.20.5", *args, "-Format", "json",
                                              "-output", "<file>", "-maxtime", "30s", "-nointeractive", "-ask", "no"]]
    assert stage.command == " ".join(masked(commands[0]))


def test_an_explicit_profile_argument_wins_and_none_falls_back_to_the_recorded_one(monkeypatch):
    """_run_nmap(), _run_whatweb() and _run_nikto() use the profile they are handed; without one they apply the
    profile recorded on the run, which is what the stage handlers rely on."""
    commands = capture_commands(monkeypatch)
    run = live_run("tprofexplicit", tools=("nmap", "whatweb", "nikto"),
                   profiles={"nmap": "quick", "whatweb": "stealthy", "nikto": "all"})
    context = web_context()
    targets = context["web_ports"]
    hybrid._run_nmap(hybrid.manager, run, run.stages[0], 100, 30.0, find_profile("nmap", "polite"))
    hybrid._run_nmap(hybrid.manager, run, run.stages[0], 100, 30.0)
    hybrid._run_whatweb(hybrid.manager, run, run.stages[1], context, targets, 30.0, find_profile("whatweb", "heavy"))
    hybrid._run_whatweb(hybrid.manager, run, run.stages[1], context, targets, 30.0)
    hybrid._run_nikto(hybrid.manager, run, run.stages[2], context, targets, 30.0, find_profile("nikto", "injection"))
    hybrid._run_nikto(hybrid.manager, run, run.stages[2], context, targets, 30.0)
    assert [c[1:4] for c in commands[:2]] == [["-sV", "-Pn", "-T2"], ["-Pn", "-T4", "--open"]]
    assert [c[2:4] for c in commands[2:4]] == [["-a", "4"], ["-a", "1"]]
    assert [c[3:5] for c in commands[4:6]] == [["-Tuning", "49c"], ["-Format", "json"]]


def test_ipv6_target_keeps_the_v6_flag_before_the_output_options_with_the_quick_profile(monkeypatch):
    """An IPv6 target is still scanned with -6, placed after the profile's arguments and the limits and before
    the XML output option, so the quick profile's shorter argument list does not displace it. A simulated run
    records the same command line, -6 included, without starting anything."""
    commands = capture_commands(monkeypatch, nmap_xml=IPV6_HOST_XML)
    run = live_run("tprofv6quick", target="2001:db8::5", profiles={"nmap": "quick"})
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "completed" and [p.port for p in run.ports] == [80]
    assert commands == [["/fake/bin/nmap", "-Pn", "-T4", "--open", "--top-ports", top_ports(), "--host-timeout", "24s",
                         "-6", "-oX", "-", "2001:db8::5"]]
    assert stage.command == " ".join(commands[0])
    simulated = live_run("tprofv6simulated", target="2001:db8::5", profiles={"nmap": "quick"})
    simulated.mode = "simulated"
    simulated_stage = run_stage_handler(hybrid.stage_port_scan, simulated)
    assert simulated_stage.status == "simulated" and len(commands) == 1
    assert simulated_stage.command == " ".join(["nmap", *commands[0][1:]]) + "  (simulated)"


def test_the_live_pipeline_applies_the_recorded_profiles_to_every_stage(monkeypatch):
    """A live run started with profiles hands each stage its profile through Run.profiles: the recorded keys, the
    three command lines and the first log line agree, and the run completes on the fakes."""
    commands = capture_commands(monkeypatch)
    request = ExecuteRequest(target="10.10.20.5", authorized=True)
    run = execute_and_wait(request, ["nmap", "whatweb", "nikto"],
                           {"nmap": "scripts", "whatweb": "aggressive", "nikto": "software"})
    try:
        assert run.status == "completed" and run.mode == "live"
        assert run.profiles == {"nmap": "scripts", "whatweb": "aggressive", "nikto": "software"}
        assert run.log[0].endswith("profiles nmap=scripts, whatweb=aggressive, nikto=software)")
        assert [os.path.basename(c[0]) for c in commands] == ["nmap", "whatweb", "nikto"]
        assert commands[0][1:6] == ["-sV", "-sC", "-Pn", "-T4", "--open"] and commands[0][-3:] == ["-oX", "-", "10.10.20.5"]
        assert commands[1][1:5] == ["--color=never", "-a", "3", "--follow-redirect=same-site"]
        assert commands[2][1:7] == ["-h", "http://10.10.20.5", "-Tuning", "be", "-Format", "json"]
        assert [s.status for s in run.stages] == ["completed"] * 3
        assert run.stages[0].command.startswith("/fake/bin/nmap -sV -sC -Pn -T4 --open --top-ports ")
        assert run.stages[1].command.startswith("/fake/bin/whatweb --color=never -a 3 --follow-redirect=same-site "
                                                "--log-json=<file> http://10.10.20.5")
        assert run.stages[2].command.startswith("/fake/bin/nikto -h http://10.10.20.5 -Tuning be -Format json "
                                                "-output <file> -maxtime ")
    finally:
        storage.delete_run(run.id)


# --- F. Simulation mode ---------------------------------------------------------------------------

def test_simulated_quick_profile_names_services_without_versions():
    """simulate_ports(target, "quick") reports the same ports and service names as the default profile but, like
    a scan without -sV, no product, version or extra detail."""
    target = simulated_port(lambda p: p.port == 8080).host
    full, hosts = simulate_ports(target)
    quick, quick_hosts = simulate_ports(target, "quick")
    assert hosts == quick_hosts == 1
    assert [(p.host, p.port, p.service, p.is_web) for p in quick] == [(p.host, p.port, p.service, p.is_web) for p in full]
    assert all(p.product == p.version == p.extra == "" for p in quick)
    assert all(p.product and p.version for p in full)


def test_simulated_scripts_profile_adds_script_notes_to_extra():
    """simulate_ports(target, "scripts") keeps the version detail and appends the notes Nmap's default scripts
    would print ("ssh-hostkey: ..." on 22, "http-title: Demo Portal" on 80); "polite" is the default scan at
    another pace, so its data is the default data."""
    target = simulated_port(lambda p: p.port == 8080).host
    scripted = {p.port: p for p in simulate_ports(target, "scripts")[0]}
    default = {p.port: p for p in simulate_ports(target, "version")[0]}
    assert scripted[22].extra == "Ubuntu Linux; protocol 2.0; ssh-hostkey: 3072 RSA, 256 ECDSA, 256 ED25519"
    assert scripted[80].extra == "http-title: Demo Portal"
    assert set(scripted) == set(default)
    for port, finding in scripted.items():
        assert (finding.product, finding.version) == (default[port].product, default[port].version)
        assert finding.extra.startswith(default[port].extra)
    assert simulate_ports(target, "polite") == simulate_ports(target, "version") == simulate_ports(target)


def test_simulated_nikto_injection_profile_reports_only_the_header_findings():
    """simulate_vulns(port, "injection") (-Tuning 49c) keeps the two untuned header findings and drops the Tomcat
    Manager (categories 2e), outdated nginx (b) and WordPress login (1e) findings, as Nikto's tuning would."""
    tomcat = simulated_port(lambda p: p.port == 8080)
    wordpress = simulated_port(lambda p: any("wp-login" in f.url for f in simulate_vulns(p)))
    for port in (tomcat, wordpress):
        findings = simulate_vulns(port, "injection")
        assert [f.description for f in findings] == HEADER_FINDINGS
        assert [f.severity for f in findings] == ["medium", "low"]  # classify_nikto()'s grades, as in a live run
        assert all(f.url == parsers.url_for(port) for f in findings)
        assert len(simulate_vulns(port)) > 2


def test_simulated_nikto_files_profile_keeps_the_tomcat_manager_and_drops_outdated_nginx():
    """simulate_vulns(port, "files") (-Tuning 123) keeps a finding only when one of its categories is in the
    tuning: the Tomcat Manager (2e) and the WordPress login page (1e) stay and outdated nginx (b) goes, while
    "software" (-Tuning be) keeps the Tomcat Manager and outdated nginx. A key that is not in the catalogue
    behaves like "all"."""
    tomcat = simulated_port(lambda p: p.port == 8080)
    files = simulate_vulns(tomcat, "files")
    assert [f.description for f in files[:2]] == HEADER_FINDINGS
    assert [f.url for f in files[2:]] == [f"{parsers.url_for(tomcat)}/manager/html"] and files[2].severity == "high"
    assert simulate_vulns(tomcat, "software") == files == simulate_vulns(tomcat, "all")
    nginx = simulated_port(lambda p: p.port == 80 and not any("wp-login" in f.url for f in simulate_vulns(p)))
    assert [f.description for f in simulate_vulns(nginx, "files")] == HEADER_FINDINGS
    assert any("appears to be outdated" in f.description for f in simulate_vulns(nginx, "software"))
    assert any("appears to be outdated" in f.description for f in simulate_vulns(nginx, "all"))
    wordpress = simulated_port(lambda p: any("wp-login" in f.url for f in simulate_vulns(p)))
    for key in ("files", "software", "all"):
        assert any(f.url.endswith("/wp-login.php") for f in simulate_vulns(wordpress, key)), key
    assert not any("outdated" in f.description for f in simulate_vulns(wordpress, "files"))
    assert simulate_vulns(tomcat, "renamed-away") == simulate_vulns(tomcat) == simulate_vulns(tomcat, "all")


def test_simulated_runs_apply_the_profiles_to_their_commands_and_data(client):
    """A simulated run shows each profile's flags in its stage commands and shapes its synthetic data the way the
    profile would: script notes on the ports and no outdated-nginx finding under the files tuning, while the
    default Nikto profile adds no -Tuning and reports it."""
    target = simulated_port(lambda p: p.port == 8080).host
    resp = start_run(client, target=target, tools=["nmap", "whatweb", "nikto"],
                     profiles={"nmap": "scripts", "whatweb": "heavy", "nikto": "files"})
    assert resp.status_code == 202, resp.text
    run = wait_for_run(client, resp.json()["id"])
    assert run["status"] == "completed" and [s["status"] for s in run["stages"]] == ["simulated"] * 3
    commands = [s["command"] for s in run["stages"]]
    assert commands[0].startswith("nmap -sV -sC -Pn -T4 --open --top-ports ")
    assert commands[0].endswith(f"-oX - {target}  (simulated)")
    assert commands[1] == "whatweb --color=never -a 4 --follow-redirect=same-site --log-json=<file> <url>  (simulated)"
    assert commands[2].startswith("nikto -h <url> -Tuning 123 -Format json -output <file> -maxtime ")
    assert commands[2].endswith("s -nointeractive -ask no  (simulated)")
    ports = {p["port"]: p for p in run["ports"]}
    assert ports[22]["product"] == "OpenSSH" and ports[22]["extra"].endswith("ssh-hostkey: 3072 RSA, 256 ECDSA, 256 ED25519")
    assert ports[80]["extra"] == "http-title: Demo Portal"
    assert any(v["url"].endswith(":8080/manager/html") for v in run["vulns"])
    assert not any("outdated" in v["description"] for v in run["vulns"])
    assert sum(v["description"] == HEADER_FINDINGS[0] for v in run["vulns"]) == len(run["web"]) > 0
    plain = wait_for_run(client, start_run(client, target=target, tools=["nmap", "whatweb", "nikto"]).json()["id"])
    assert plain["stages"][0]["command"].startswith("nmap -sV -Pn -T4 --open --top-ports ")
    assert plain["stages"][2]["command"].startswith("nikto -h <url> -Format json -output <file> -maxtime ")
    assert "-Tuning" not in plain["stages"][2]["command"]
    assert any("appears to be outdated" in v["description"] for v in plain["vulns"])


def test_simulated_whatweb_data_does_not_change_with_its_profile(client):
    """The WhatWeb profile changes only the aggression level on the command line: the synthetic fingerprint of a
    target is the same under stealthy and heavy, so a simulated comparison shows no technology change, only
    the profile note."""
    target = simulated_port(lambda p: p.port == 8080).host
    runs = [wait_for_run(client, start_run(client, target=target, tools=["nmap", "whatweb"],
                                           profiles={"whatweb": key}).json()["id"]) for key in ("stealthy", "heavy")]
    assert runs[0]["web"] == runs[1]["web"] and runs[0]["web"]
    assert runs[0]["summary"]["technologies"] == runs[1]["summary"]["technologies"] > 0
    assert [r["stages"][1]["command"].split(" -a ")[1][:1] for r in runs] == ["1", "4"]
    diff = client.get("/api/compare", params={"base": runs[0]["id"], "other": runs[1]["id"]}).json()
    assert diff["tech_added"] == [] and diff["tech_removed"] == []
    assert diff["note"] == ("The runs used different profiles for whatweb (Stealthy, level 1 vs Heavy, level 4), so some "
                            "differences may come from the profile rather than from the target.")


# --- G. The parser's script notes -----------------------------------------------------------------

def test_nmap_parser_appends_script_notes_after_the_service_detail():
    """Each <script> under an open port becomes an "id: output" note in PortFinding.extra, after the service's
    extrainfo and joined with "; "; a port with scripts but no extrainfo gets the notes alone, and a port
    without scripts, or one that is not open, is read exactly as before."""
    ports = {p.port: p for p in parsers.parse_nmap_xml(SCRIPTED_HOST_XML)[0]}
    assert set(ports) == {22, 80, 3306}
    assert ports[22].extra == ("Ubuntu Linux; protocol 2.0; ssh-hostkey: 3072 SHA256:aaaa (RSA) 256 SHA256:bbbb (ECDSA); "
                               "banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert (ports[22].service, ports[22].product, ports[22].version) == ("ssh", "OpenSSH", "9.6p1")
    assert ports[80].extra == "http-title: Demo Portal" and ports[80].is_web is True
    assert ports[3306].extra == "unauthorized"
    plain = {p.port: p for p in parsers.parse_nmap_xml(re.sub(r"<script [^>]*/>", "", SCRIPTED_HOST_XML))[0]}
    assert plain[3306] == ports[3306]
    for port in (22, 80):
        assert plain[port].model_dump(exclude={"extra"}) == ports[port].model_dump(exclude={"extra"})


def test_nmap_parser_collapses_script_output_and_caps_the_notes():
    """Multi-line script output (Nmap writes the line breaks as character references) is collapsed to one line of
    single spaces; a note longer than MAX_SCRIPT_NOTE_CHARS (120) is cut at a word boundary and ends in "..." so
    a cut value never reads as complete (one unbroken token is cut mid-way instead of dropped); at most
    MAX_SCRIPT_NOTES (3) notes are kept per port, unranked scripts in document order, so a chatty script cannot
    bloat the port's extra column. A script without an id or without output is skipped and uses no slot."""
    assert (parsers.MAX_SCRIPT_NOTES, parsers.MAX_SCRIPT_NOTE_CHARS) == (3, 120)
    xml = _port_xml('<script id="ssl-cert" output="' + "X" * 300 + '"/>'
                    '<script id="http-headers" output="&#10;  Server:   nginx&#10;&#9;Date: now&#10;"/>')
    [port] = parsers.parse_nmap_xml(xml)[0]
    assert port.extra == "ssl-cert: " + "X" * 117 + "...; http-headers: Server: nginx Date: now"
    words = " ".join(f"word{n:02d}" for n in range(40))  # 279 characters of seven-character words
    [port] = parsers.parse_nmap_xml(_port_xml(f'<script id="ssl-cert" output="{words}"/>'))[0]
    note = port.extra.removeprefix("ssl-cert: ")
    assert note.endswith("...") and len(note) <= 120 and note[:-3] == words[:len(note) - 3]
    assert not words[len(note) - 3].strip()  # the cut falls on a space, never inside a word
    xml = _port_xml('<script id="blank" output=""/><script output="no id"/>'
                    + "".join(f'<script id="s{n}" output="note {n}"/>' for n in range(1, 6)))
    [port] = parsers.parse_nmap_xml(xml)[0]
    assert port.extra == "s1: note 1; s2: note 2; s3: note 3"


def test_nmap_parser_ranks_the_useful_scripts_and_ignores_the_chatter():
    """Nmap lists a port's scripts alphabetically, so on an HTTPS port the http-* results would fill the three
    slots before ssl-cert. The parser ranks PREFERRED_SCRIPTS first (ssl-cert, ssh-hostkey, http-title, ...) and
    drops IGNORED_SCRIPTS (http-methods, http-server-header, ssl-date, tls-alpn, ...), which repeat what -sV
    reported or carry no observation, so the certificate the scripts profile promises is kept."""
    assert parsers.PREFERRED_SCRIPTS[:3] == ("ssl-cert", "ssh-hostkey", "http-title")
    assert {"http-methods", "http-server-header", "ssl-date", "tls-alpn", "tls-nextprotoneg"} <= parsers.IGNORED_SCRIPTS
    assert not set(parsers.PREFERRED_SCRIPTS) & parsers.IGNORED_SCRIPTS
    xml = _port_xml('<script id="http-methods" output="GET HEAD POST"/>'
                    '<script id="http-server-header" output="nginx/1.18.0"/>'
                    '<script id="http-title" output="Demo Portal"/>'
                    '<script id="ssl-cert" output="Subject: commonName=demo.lab"/>'
                    '<script id="ssl-date" output="2026-11-04T12:00:00+00:00; 0s from scanner time."/>'
                    '<script id="tls-alpn" output="h2 http/1.1"/>'
                    '<script id="http-robots.txt" output="1 disallowed entry /admin/"/>'
                    '<script id="some-other-script" output="extra"/>')
    [port] = parsers.parse_nmap_xml(xml)[0]
    assert port.extra == ("ssl-cert: Subject: commonName=demo.lab; http-title: Demo Portal; "
                          "http-robots.txt: 1 disallowed entry /admin/")


# --- H. Runs stored before profiles existed -------------------------------------------------------

def test_runs_stored_before_profiles_existed_load_with_empty_profiles(client):
    """A run document without the "profiles" field (saved by an earlier version) loads with {} from storage.get_run,
    storage.list_runs and the API, is reported with its tools alone, and compares as a default-profile run.
    The history list also tolerates a document whose profiles or summary field is null."""
    run = make_run(id="tprofold0001", target="10.10.20.5", tools=["nmap", "whatweb"], profiles={"nmap": "quick"},
                   ports=[PortFinding(host="10.10.20.5", port=80, service="http", is_web=True)],
                   stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                           StageResult(stage="web_fingerprint", tool="whatweb", status="completed")])
    document = json.loads(run.model_dump_json())
    del document["profiles"]
    nulled = dict(document, id="tprofold0002", profiles=None, summary=None)
    quick = completed_run("tprofold0003", ["nmap", "whatweb"], {"nmap": "quick", "whatweb": "stealthy"}, ports=run.ports)
    with storage.connect() as conn:
        for doc in (document, nulled):
            conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) VALUES (?, ?, ?, ?, ?)",
                         (doc["id"], doc["created_at"], doc["target"], doc["status"], json.dumps(doc)))
    storage.save_run(quick)
    try:
        stored = storage.get_run(run.id)
        assert stored.profiles == {} and stored.tools == ["nmap", "whatweb"]
        assert stored.custom_tools == {} and stored.custom_outputs == []  # saved before custom tools existed
        listed = {item.id: item for item in storage.list_runs()}
        assert listed[run.id].profiles == {} and listed[nulled["id"]].profiles == {}
        assert listed[nulled["id"]].summary == RunSummary() and storage.get_run(nulled["id"]).summary == RunSummary()
        # Other nulls (inside the summary, mode, tools, a profile key) and a summary that is not an object load
        # with their defaults on both paths, and a document that is still unreadable is left out of the list
        # instead of failing it for everyone.
        damaged = {
            "tprofold0004": dict(document, summary={"highlights": None, "risk_score": None, "partial": None}),
            "tprofold0005": dict(document, mode=None, tools=None, profiles={"nmap": None}, custom_tools=None,
                                 custom_outputs=None),
            "tprofold0006": dict(document, summary=[]),
            "tprofold0007": dict(document, summary={"risk_score": 250}),
            "tprofold0008": dict(document, status=None),
            "tprofold0009": dict(document, summary={"risk_score": float("inf")}),  # 1e999 in the JSON
        }
        with storage.connect() as conn:
            for doc_id, doc in damaged.items():
                conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) "
                             "VALUES (?, ?, ?, ?, ?)", (doc_id, doc["created_at"], doc["target"], "completed",
                                                     json.dumps(dict(doc, id=doc_id))))
            # A pathologically nested document (json.loads raises RecursionError) is skipped like the others.
            deep = json.dumps(dict(document, id="tprofold0010"))[:-1] + ', "deep": ' + "[" * 100000 + "]" * 100000 + "}"
            conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) "
                         "VALUES (?, ?, ?, ?, ?)", ("tprofold0010", document["created_at"], document["target"],
                                                 "completed", deep))
        history = client.get("/api/runs")
        assert history.status_code == 200 and run.id in {item["id"] for item in history.json()}
        listed = {item["id"]: item for item in history.json()}
        # Unreadable documents are listed as "unreadable" (so they can be deleted), never a 500; opening one says why.
        assert listed["tprofold0008"]["status"] == listed["tprofold0010"]["status"] == "unreadable"
        assert history.headers["X-Total-Count"] == str(len(storage.list_runs(limit=1000)))
        assert client.get("/api/runs/tprofold0010").status_code == 422
        assert listed["tprofold0007"]["summary"]["risk_score"] == 100
        assert listed["tprofold0009"]["summary"]["risk_score"] == 0
        for doc_id in ("tprofold0004", "tprofold0005", "tprofold0006", "tprofold0007", "tprofold0009"):
            assert client.get(f"/api/runs/{doc_id}").status_code == 200, doc_id
            assert listed[doc_id]["summary"] == client.get(f"/api/runs/{doc_id}").json()["summary"], doc_id
        assert listed["tprofold0005"]["mode"] == "live" and listed["tprofold0005"]["profiles"] == {}
        assert client.get("/api/runs/tprofold0005").json()["custom_outputs"] == []
        assert client.get(f"/api/runs/{nulled['id']}").json()["summary"]["risk_score"] == 0
        assert client.get(f"/api/runs/{run.id}").json()["profiles"] == {}
        api_listed = {item["id"]: item for item in client.get("/api/runs").json()}
        assert api_listed[run.id]["profiles"] == {} and api_listed[nulled["id"]]["profiles"] == {}
        assert tools_with_profiles(stored) == "nmap, whatweb"
        assert "**Tools:** nmap, whatweb  " in client.get(f"/api/runs/{run.id}/report", params={"format": "md"}).text
        assert "tools: nmap, whatweb &middot;" in client.get(f"/api/runs/{run.id}/report", params={"format": "html"}).text
        diff = client.get("/api/compare", params={"base": run.id, "other": quick.id}).json()
        assert diff["note"] == PROFILE_NOTE
        assert diff["base"]["profiles"] == {} and diff["other"]["profiles"] == {"nmap": "quick", "whatweb": "stealthy"}
        default = quick.model_copy(update={"id": "tprofold0004", "profiles": {"nmap": "version", "whatweb": "stealthy"}})
        assert compare_runs(stored, default).note is None and compare_runs(default, stored).note is None
    finally:
        for run_id in (run.id, nulled["id"], quick.id, *(f"tprofold{n:04d}" for n in range(4, 11))):
            storage.delete_run(run_id)


# --- I. Reports -----------------------------------------------------------------------------------

def test_reports_name_the_profile_each_tool_used():
    """The Markdown "Tools" line and the HTML meta line show every tool with the label of its profile; a tool
    without a recorded profile is listed by name alone, a key no longer in the catalogue is shown as stored
    (escaped like any tool output), and a profile recorded for a tool the run did not use is ignored."""
    run = completed_run("tprofrep0001", ["nmap", "whatweb", "nikto"],
                        {"nmap": "quick", "whatweb": "stealthy", "nikto": "injection"})
    labelled = "nmap (Quick port scan), whatweb (Stealthy, level 1), nikto (Injection checks)"
    assert tools_with_profiles(run) == labelled
    assert f"**Tools:** {labelled}  " in render_markdown(run)
    assert f"tools: {labelled} &middot;" in render_html(run)

    def listed(profiles: dict[str, str]) -> str:
        return tools_with_profiles(completed_run("tprofrep0002", ["nmap", "whatweb"], profiles))

    assert listed({}) == "nmap, whatweb"
    assert listed({"nmap": "quick"}) == "nmap (Quick port scan), whatweb"
    assert listed({"nmap": "legacy", "whatweb": "stealthy"}) == "nmap (legacy), whatweb (Stealthy, level 1)"
    assert listed({"nikto": "files"}) == "nmap, whatweb"
    odd = completed_run("tprofrep0003", ["nmap"], {"nmap": "legacy<b>"})
    assert "**Tools:** nmap (legacy&lt;b&gt;)  " in render_markdown(odd)
    assert "tools: nmap (legacy&lt;b&gt;) &middot;" in render_html(odd)
    mixed = completed_run("tprofrep0004", ["nmap"], {"nmap": "quick"})
    mixed.tools = ["nmap", "hdrcheck"]
    mixed.custom_tools = {"hdrcheck": CustomTool(name="hdrcheck", program="curl", args=["-sI", "{url}"], scope="url",
                                                 created_at=mixed.created_at)}
    assert tools_with_profiles(mixed) == "nmap (Quick port scan), hdrcheck (custom)"


def test_csv_report_keeps_its_fifteen_columns_without_a_profile_column():
    """Profiles are not a CSV column: the header and every row still have the same 15 cells as before."""
    run = completed_run("tprofcsv0001", ["nmap", "whatweb", "nikto"], {"nmap": "quick", "whatweb": "heavy", "nikto": "files"},
                        ports=[PortFinding(host="10.10.20.5", port=80, service="http", is_web=True)],
                        web=[WebFinding(url="http://10.10.20.5", host="10.10.20.5", port=80, status_code=200, title="Demo",
                                        technologies=[{"name": "nginx", "version": "1.18.0"}])],
                        vulns=[VulnFinding(url="http://10.10.20.5", severity="low", description=HEADER_FINDINGS[0])])
    text = render_csv(run)
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["section", "host", "port", "protocol", "service", "product", "version", "url", "technology",
                       "tech_version", "severity", "description", "reference", "coverage", "mode"]
    assert len(rows) == 4 and all(len(row) == 15 for row in rows)
    assert "quick" not in text and "Quick port scan" not in text


# --- J. The comparison note -----------------------------------------------------------------------

def test_compare_warns_when_the_runs_used_different_profiles():
    """When the two runs used different profiles for a tool they share, the note names the tool with both labels
    (base first), lists every such tool, and says the difference may come from the profile."""
    base = completed_run("tprofcmp0001", ["nmap", "whatweb"], {"nmap": "version", "whatweb": "stealthy"})
    other = completed_run("tprofcmp0002", ["nmap", "whatweb"], {"nmap": "quick", "whatweb": "stealthy"})
    assert compare_runs(base, other).note == PROFILE_NOTE
    assert compare_runs(other, base).note == PROFILE_NOTE.replace(
        "(Service and version detection vs Quick port scan)", "(Quick port scan vs Service and version detection)")
    three = completed_run("tprofcmp0003", ["nmap", "whatweb", "nikto"],
                          {"nmap": "quick", "whatweb": "heavy", "nikto": "injection"})
    assert compare_runs(base, three).note == (
        "Nikto ran only in the other run, so what it found appears here as removed or added although the run "
        "without it never looked for it. "
        "The runs used different profiles for nmap (Service and version detection vs Quick port scan), "
        "whatweb (Stealthy, level 1 vs Heavy, level 4), so some differences may come from the profile rather than "
        "from the target.")


def test_compare_stays_silent_when_the_profiles_match_or_the_tools_differ():
    """No profile note when every shared tool used the same profile, when the runs share no tool (the tool-set
    note says so instead), or when a run's stored key is unknown (it counts as the default); a tool that is no
    longer in the catalogue does not break the comparison."""
    base = completed_run("tprofcmp0011", ["nmap", "whatweb"], {"nmap": "quick", "whatweb": "heavy"})
    same = completed_run("tprofcmp0012", ["nmap", "whatweb"], {"nmap": "quick", "whatweb": "heavy"})
    assert compare_runs(base, base).note is None and compare_runs(base, same).note is None
    unrelated = completed_run("tprofcmp0013", ["nikto"], {"nikto": "injection"})
    assert compare_runs(base, unrelated).note == (
        "Nmap and WhatWeb ran only in the base run and Nikto ran only in the other run, so what they found appears "
        "here as removed or added although the run without them never looked for it.")
    assert "profiles" not in compare_runs(unrelated, base).note
    foreign_stages = [StageResult(stage="port_scan", tool="nmap", status="completed"),
                      StageResult(stage="dns_lookup", tool="dns", status="completed")]
    foreign = make_run(id="tprofcmp0016", target="10.10.20.5", tools=["nmap", "dns"], stages=foreign_stages,
                       profiles={"nmap": "version", "dns": "fast"})
    foreign_other = foreign.model_copy(update={"id": "tprofcmp0017", "profiles": {"nmap": "version", "dns": "slow"}})
    assert compare_runs(foreign, foreign).note is None  # the unknown tool's keys are compared as text
    assert compare_runs(foreign, foreign_other).note == (
        "The runs used different profiles for dns (fast vs slow), so some differences may come from the profile "
        "rather than from the target.")
    # A foreign tool with a recorded key on one side only has nothing to compare it with: no empty label.
    unrecorded = foreign.model_copy(update={"id": "tprofcmp0018", "profiles": {"nmap": "version"}})
    assert compare_runs(unrecorded, foreign).note is None and compare_runs(foreign, unrecorded).note is None
    renamed = completed_run("tprofcmp0014", ["nmap"], {"nmap": "renamed-away"})
    default = completed_run("tprofcmp0015", ["nmap"], {"nmap": "version"})
    assert compare_runs(renamed, default).note is None and compare_runs(default, renamed).note is None
    # Custom tool output is never compared, so a custom tool gets its own note instead of the tool-set note.
    hdrcheck = CustomTool(name="hdrcheck", program="curl", args=["-sI", "{url}"], scope="url", created_at=base.created_at)
    with_custom = base.model_copy(deep=True, update={
        "id": "tprofcmp0019", "tools": [*base.tools, "hdrcheck"], "custom_tools": {"hdrcheck": hdrcheck},
        "stages": [*base.stages, StageResult(stage="custom_tool", tool="hdrcheck", status="simulated")]})
    note = compare_runs(base, with_custom).note
    assert note == ("Output of the custom tool(s) hdrcheck is kept as raw text and is not compared. The runs used "
                    "different custom tools, which share the time budget with the built-in tools, so the built-in "
                    "stages may have had different time.")
    assert compare_runs(with_custom, with_custom).note == ("Output of the custom tool(s) hdrcheck is kept as raw text "
                                                           "and is not compared.")


def test_compare_joins_the_coverage_note_and_the_profile_note():
    """When a run is partial and the profiles differ, both warnings are given in one note, coverage first."""
    partial = completed_run("tprofcmp0021", ["nmap"], {"nmap": "version"}, summary=RunSummary(partial=True))
    quick = completed_run("tprofcmp0022", ["nmap"], {"nmap": "quick"})
    assert compare_runs(partial, quick).note == (
        "The base run has partial results (see the stage notes), so anything missing from it is not evidence "
        "that it disappeared or appeared. " + PROFILE_NOTE)
    reverse = compare_runs(quick, partial).note
    assert reverse.startswith("The other run has partial results")
    assert reverse.endswith("nmap (Quick port scan vs Service and version detection), so some differences may come "
                            "from the profile rather than from the target.")
    assert compare_runs(partial, partial).note.startswith("Both runs have partial results")
    assert "profiles" not in compare_runs(partial, partial).note


def test_compare_treats_a_run_without_profiles_as_having_used_the_defaults():
    """A run recorded before profiles existed (profiles == {}) compares as a default-profile run: no note against
    a default run, the usual note against a quick scan, with the defaults' labels in it."""
    old = completed_run("tprofcmp0031", ["nmap", "whatweb", "nikto"], {})
    assert old.profiles == {}
    default = completed_run("tprofcmp0032", ["nmap", "whatweb", "nikto"],
                            {"nmap": "version", "whatweb": "stealthy", "nikto": "all"})
    assert compare_runs(old, default).note is None and compare_runs(default, old).note is None
    quick = completed_run("tprofcmp0033", ["nmap", "whatweb", "nikto"],
                          {"nmap": "quick", "whatweb": "stealthy", "nikto": "files"})
    assert compare_runs(old, quick).note == (
        "The runs used different profiles for nmap (Service and version detection vs Quick port scan), "
        "nikto (All checks vs Files and misconfiguration), so some differences may come from the profile rather "
        "than from the target.")


# --- K. Dashboard (static checks) -----------------------------------------------------------------

def test_dashboard_new_run_form_offers_a_labelled_profile_select_per_tool_and_sends_the_choices():
    """app.js defines the four profile helpers; each tool row carries a <select class="tool-profile-select"
    id="run-profile-<tool>"> with a screen-reader label naming the tool, options that are the escaped labels
    from /api/tools with the default (or the kept choice) selected, and a hint that explains the choice; the
    control is disabled while the tool is unticked; submit sends the ticked tools' choices as body.profiles;
    the tool rows live in #run-tools and DEFAULT_TOOLS is still consulted twice."""
    js = _js()
    for helper in ("profileSelectHtml(tool, chosenKey, disabled)", "updateProfileHint(select)",
                   "currentToolSelection()", "profileLabel(tool, key)"):
        assert f"function {helper} {{" in js, helper
    assert 'const id = "run-profile-" + tool.name;' in js
    assert ('\'<label class="sr-only" for="\' + esc(id) + \'">\' + esc(tool.display_name || tool.name) '
            '+ " profile</label>"') in js
    assert ('\'<select id="\' + esc(id) + \'" class="tool-profile-select" data-tool="\' + esc(tool.name) + \'" '
            'aria-describedby="\' + esc(id) + \'-hint"\' + (disabled ? " disabled" : "") + ">"') in js
    assert '\'<div class="hint tool-profile-hint" id="\' + esc(id) + \'-hint"></div>\'' in js   # the described-by target
    assert "const fallback = profiles.find((p) => p.default) || profiles[0];" in js
    assert "const current = profiles.some((p) => p.key === chosenKey) ? chosenKey : fallback.key;" in js
    assert '(p.key === current ? " selected" : "") + ">" + esc(p.label) + "</option>"' in js
    assert "profileSelectHtml(t, keptProfiles[name], !on)" in js
    assert '$$(".tool-profile-select", wrap).forEach(updateProfileHint);' in js
    assert '"Adds: " + profile.flags' in js and '"No extra options."' in js
    assert "if (select) select.disabled = !el.checked;" in js
    assert 'else if (el.matches(".tool-profile-select")) {' in js and "updateProfileHint(el);" in js
    assert "const selection = currentToolSelection();" in js and "const tools = selection.tools;" in js
    assert "if (select && select.value) selection.profiles[input.value] = select.value;" in js
    assert "if (Object.keys(selection.profiles).length) body.profiles = selection.profiles;" in js
    assert js.count("DEFAULT_TOOLS.includes(") == 2
    assert '<div class="tool-rows" id="run-tools">' in (DASHBOARD / "index.html").read_text(encoding="utf-8")


def test_dashboard_shows_the_profile_in_the_timeline_and_the_runs_table():
    """renderTimeline() takes the run's profiles and shows each stage's profile label next to the tool, on the
    first paint and on the live patch, and the Runs table's tool chips carry the profile label as their title."""
    js = _js()
    assert "function renderTimeline(stages, profiles) {" in js
    assert js.count("renderTimeline(run.stages, run.profiles)") == 2
    assert 'const profile = profiles && s.tool && profiles[s.tool] ? profileLabel(s.tool, profiles[s.tool]) : "";' in js
    assert ('(profile ? \'<span class="tl-profile" title="Profile: the option set chosen for this tool">\' '
            '+ esc(profile) + "</span>" : "")') in js
    assert ('\'<td class="col-tools">\' + chips(r.tools, "chip-muted", '
            '(t) => (r.profiles && r.profiles[t] ? profileLabel(t, r.profiles[t]) : "")) + "</td>"') in js
    assert 'const title = titleFor ? titleFor(i) : "";' in js and "' title=\"' + esc(title) + '\"'" in js


def test_dashboard_styles_stack_the_tool_rows_and_set_off_the_profile_controls():
    """styles.css lays the tool rows out as a column, indents each profile control under its checkbox behind a
    left border, bounds the drop-down's width, and dims the control and the hint of an unticked tool."""
    css = _css()
    assert ".tool-rows { display: flex; flex-direction: column;" in css
    assert ".tool-row { display: flex; flex-direction: column; gap: 6px; min-width: 0; }" in css
    profile = _rule(css, r"\.tool-profile")
    assert "margin-left: 12px" in profile and "padding-left: 12px" in profile
    assert "border-left: 2px solid var(--border)" in profile
    assert ".tool-profile-select { max-width: 420px; }" in css
    assert ".tool-profile-select:disabled { opacity: 0.55; cursor: not-allowed; }" in css
    assert ".tool-row.disabled .tool-profile-hint { opacity: 0.55; }" in css
