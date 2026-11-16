"""Detailed edge-case tests for the pipeline engine (app/hybrid.py) and the AI planner (app/planner.py).

Every test checks one behaviour and names it. The suite runs offline: scanners are replaced with fakes
through monkeypatch, runs use simulation mode, and the AI providers are replaced with in-process fakes, so
no scanner is ever started, no network request leaves the machine and no real API key is read. Importing
tests.test_api first points the app at a private .env file, a temporary data directory and the rules planner.
"""
from __future__ import annotations

import io
import json
import sys
import time
import types
from itertools import combinations
from types import SimpleNamespace
from typing import get_args

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import hybrid, planner, storage
from app.config import settings
from app.hybrid import (
    MAX_WEB_TARGETS,
    SEVERITY_WEIGHT,
    STAGE_MIN_SECONDS,
    RunLimitExceeded,
    RunManager,
    _final_outcome,
    _highlights,
    _probe_host,
    _risk_score,
    _stage_budgets,
    _stage_end,
    _time_for_next_url,
    _web_targets,
    simulate_ports,
    simulate_vulns,
    simulate_web,
    summarize,
)
from app.main import app
from app.planner import (
    EXECUTOR_COMMANDS,
    PLAN_SCHEMA,
    SYSTEM_PROMPT,
    _normalize_plan,
    create_plan,
    describe_error,
    refine_plan,
    rules_plan,
)
from app.schemas import (
    CustomTool,
    ExecuteRequest,
    Plan,
    PlanRequest,
    PlanResponse,
    PlanStep,
    PortFinding,
    RefineRequest,
    Run,
    SafetyControls,
    StageResult,
    VulnFinding,
    WebFinding,
)
from app.tools import parsers, runner
from app.tools.custom import RUN_OUTPUT_CHARS, STDOUT_CHARS
from app.tools.registry import TOOLS
from app.tools.runner import CommandResult
from tests.test_api import fake_scanner, make_run, run_stage_handler

OBJECTIVE = "Plan a hybrid assessment of an authorized lab host: ports first, then web technologies."
ALL_TOOLS = ["nmap", "whatweb", "nikto"]

NMAP_HEAD = '<?xml version="1.0"?><nmaprun scanner="nmap">'
NMAP_SSH_ONLY = (NMAP_HEAD + '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/><ports>'
                 '<port protocol="tcp" portid="22"><state state="open"/>'
                 '<service name="ssh" product="OpenSSH" version="8.9"/></port></ports></host></nmaprun>')
NMAP_NO_HOSTS = NMAP_HEAD + '<runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>'


# --- Fixtures and helpers -------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def database_tables():
    """Runs are saved to SQLite; the app's startup normally creates the tables, so create them here."""
    storage.init_db()


def wait_for(predicate, timeout: float = 5.0, interval: float = 0.02) -> bool:
    """Poll `predicate` in short steps until it is true or `timeout` seconds have passed."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def execute_and_wait(manager: RunManager, request: ExecuteRequest, tools: list[str], budget: int = 60,
                     custom_tools: dict[str, CustomTool] | None = None) -> Run:
    """Start a run on `manager` and return its stored final state once the worker thread has finished."""
    run = manager.create(request, request.target, tools, None, budget, None, custom_tools)
    assert wait_for(lambda: not manager.is_active(run.id)), "the run did not finish in time"
    return storage.get_run(run.id)


def three_stage_run(**fields) -> Run:
    """A running live-mode Run with the three pipeline stages still pending."""
    values = {"id": "p3000000001", "target": "10.10.20.5", "status": "running", "tools": list(ALL_TOOLS),
              "stages": [StageResult(stage=TOOLS[t].stage, tool=t) for t in ALL_TOOLS]}
    values.update(fields)
    return make_run(**values)


def vuln(severity: str, description: str, url: str = "http://10.10.20.5") -> VulnFinding:
    return VulnFinding(url=url, severity=severity, description=description)


def web(url: str, technologies: list[dict], reachable: bool = True, port: int = 80) -> WebFinding:
    return WebFinding(url=url, host="10.10.20.5", port=port, status_code=200, technologies=technologies,
                      reachable=reachable)


def port(number: int, service: str) -> PortFinding:
    return PortFinding(host="10.10.20.5", port=number, service=service)


# --- Simulation mode ------------------------------------------------------------------------------

def test_simulation_is_deterministic_for_the_same_target():
    """The same target always produces identical simulated ports, technologies and findings."""
    first, second = simulate_ports("127.0.0.1"), simulate_ports("127.0.0.1")
    assert first == second
    for port_a, port_b in zip(first[0], second[0], strict=True):
        if port_a.is_web:
            assert simulate_web(port_a) == simulate_web(port_b)
            assert simulate_vulns(port_a) == simulate_vulns(port_b)


def test_simulation_differs_between_targets():
    """Different targets give different simulated results, so comparisons between runs stay meaningful."""
    loopback = {p.port for p in simulate_ports("127.0.0.1")[0]}
    lab_host = {p.port for p in simulate_ports("10.10.20.5")[0]}
    assert loopback != lab_host


@pytest.mark.parametrize("target", ["127.0.0.1", "10.10.20.5", "lab.example.edu", "::1"])
def test_simulation_always_reports_ssh_and_http_on_one_live_host(target):
    """Every simulated scan finds SSH and HTTP open on exactly one host, and every port is an open TCP port."""
    ports, hosts_up = simulate_ports(target)
    assert hosts_up == 1
    assert {22, 80} <= {p.port for p in ports}
    assert all(p.state == "open" and p.protocol == "tcp" and p.host == target for p in ports)


def test_simulation_uses_the_first_usable_address_for_a_cidr_target():
    """A simulated range scan reports its findings on the range's first usable address, as a real scan would
    (the network address itself is never a live host), not on the CIDR string."""
    ports, _ = simulate_ports("10.10.20.0/24")
    assert {p.host for p in ports} == {"10.10.20.1"}
    assert {p.host for p in simulate_ports("10.10.20.5/32")[0]} == {"10.10.20.5"}


@pytest.mark.parametrize("product,title,technology,severities", [
    ("Apache Tomcat", "Apache Tomcat/9.0.65", "Apache Tomcat", {"low", "medium", "high"}),
    ("Jetty", "Jenkins [Jenkins]", "Jetty", {"low", "medium"}),
    ("nginx", "Demo Portal", "nginx", {"low", "medium"}),
])
def test_simulated_web_and_vuln_results_follow_the_product_on_the_port(product, title, technology, severities):
    """The simulated fingerprint and findings match the product Nmap reported on that port, and every finding
    carries the grade classify_nikto() gives the same message in a live run."""
    finding = PortFinding(host="127.0.0.1", port=8080, service="http", product=product, is_web=True)
    fingerprint = simulate_web(finding)
    assert fingerprint.title == title and fingerprint.url == "http://127.0.0.1:8080"
    assert technology in {t["name"] for t in fingerprint.technologies}
    vulns = simulate_vulns(finding)
    assert {v.severity for v in vulns} == severities
    assert [v.severity for v in vulns] == [parsers.classify_nikto(v.description) for v in vulns]
    assert all(v.url.startswith("http://127.0.0.1:8080") for v in vulns)


# --- Run lifecycle through RunManager --------------------------------------------------------------

def test_finished_run_records_timestamps_and_duration():
    """A finished run has start and finish times, a matching duration, timed stages and a closing log line."""
    run = execute_and_wait(RunManager(), ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True),
                           list(ALL_TOOLS))
    assert run.status == "completed" and run.error is None
    assert run.started_at is not None and run.finished_at is not None and run.started_at <= run.finished_at
    assert run.duration_seconds == pytest.approx((run.finished_at - run.started_at).total_seconds(), abs=0.001)
    assert all(s.started_at and s.finished_at and s.duration_seconds >= 0 for s in run.stages)
    assert run.log[-1].endswith(f"run completed in {run.duration_seconds}s")


def test_stages_run_in_pipeline_order_and_are_marked_simulated():
    """A simulated run executes port_scan, web_fingerprint and web_vuln_scan in that order, all 'simulated'."""
    run = execute_and_wait(RunManager(), ExecuteRequest(target="10.10.20.5", authorized=True, simulate=True),
                           list(ALL_TOOLS))
    assert [(s.stage, s.tool) for s in run.stages] == [("port_scan", "nmap"), ("web_fingerprint", "whatweb"),
                                                        ("web_vuln_scan", "nikto")]
    assert {s.status for s in run.stages} == {"simulated"} and run.mode == "simulated"
    assert all("(simulated)" in s.command for s in run.stages)
    # Custom tools run last, simulated without their program, once per URL Nikto scans or once on the target. The
    # text is the same every time, and no count or score changes.
    custom = {"hdrcheck": CustomTool(name="hdrcheck", program="curl", args=["-sI", "{url}"], scope="url",
                                     created_at=run.created_at),
              "whoisq": CustomTool(name="whoisq", program="whois", args=["{target}"], scope="target",
                                   created_at=run.created_at)}
    request = ExecuteRequest(target="10.10.20.5", authorized=True, simulate=True)
    from unittest import mock
    with mock.patch.object(hybrid, "find_program", side_effect=AssertionError("simulation looked the program up")):
        first, second = [execute_and_wait(RunManager(), request, [*ALL_TOOLS, "hdrcheck", "whoisq"], custom_tools=custom)
                         for _ in range(2)]
    assert [(s.stage, s.tool, s.status) for s in first.stages[3:]] == [("custom_tool", "hdrcheck", "simulated"),
                                                                        ("custom_tool", "whoisq", "simulated")]
    assert all("(simulated)" in s.command for s in first.stages[3:])
    assert [o.target for o in first.custom_outputs if o.tool == "hdrcheck"] == [w.url for w in first.web if w.reachable]
    whois = [o for o in first.custom_outputs if o.tool == "whoisq"]
    assert len(whois) == 1 and whois[0].target == "10.10.20.5" and "It would have run: whois 10.10.20.5" in whois[0].stdout
    assert [(o.target, o.command, o.stdout) for o in first.custom_outputs] == \
        [(o.target, o.command, o.stdout) for o in second.custom_outputs]
    # A simulated call never ran a program, so it is recorded as simulated with no exit code of its own.
    assert {(o.ended, o.exit_code, o.timed_out) for o in first.custom_outputs} == {("simulated", None, False)}
    assert (first.summary.risk_score, first.summary.vulnerabilities, first.summary.partial) == \
        (run.summary.risk_score, run.summary.vulnerabilities, False)


def test_stage_status_vocabulary_is_fixed():
    """A stage can only be pending, running, completed, failed, skipped or simulated; anything else is rejected."""
    allowed = set(get_args(StageResult.model_fields["status"].annotation))
    assert allowed == {"pending", "running", "completed", "failed", "skipped", "simulated"}
    with pytest.raises(ValidationError):
        StageResult(stage="port_scan", tool="nmap", status="done")


def test_nmap_failure_fails_the_run_and_skips_the_web_stages_with_a_reason(monkeypatch):
    """When Nmap fails, the run fails and WhatWeb and Nikto are skipped with a reason, never started."""
    fake_scanner(monkeypatch, stdout="", stderr="QUITTING! Could not open the network interface.", exit_code=1)
    run = execute_and_wait(RunManager(), ExecuteRequest(target="10.10.20.5", authorized=True), list(ALL_TOOLS))
    assert run.status == "failed" and run.error == run.stages[0].error
    assert run.stages[0].status == "failed" and "QUITTING" in run.stages[0].error
    assert run.stages[1].status == "skipped"
    # A failed first stage is named as the reason, not a result no stage produced (issue 28).
    assert run.stages[1].error == "The first stage failed, so WhatWeb did not run."
    assert run.stages[2].status == "skipped"
    assert run.stages[2].error == "The first stage failed, so Nikto did not run."


def test_no_open_web_ports_skips_whatweb_and_nikto_but_completes_the_run(monkeypatch):
    """A host with only SSH open completes the run: the web stages are skipped, which is not a failure."""
    fake_scanner(monkeypatch, stdout=NMAP_SSH_ONLY)
    run = execute_and_wait(RunManager(), ExecuteRequest(target="10.10.20.5", authorized=True), list(ALL_TOOLS))
    assert run.status == "completed" and run.error is None
    assert [s.status for s in run.stages] == ["completed", "skipped", "skipped"]
    # Live custom tools go through the same runner: an argument list starting with the program that was found, the
    # output limit, and a time limit no longer than the tool's own. A non-zero exit code is not a failure. A per-URL
    # tool is skipped like Nikto when no URL answered.
    calls = []

    def recording(command, timeout, max_chars=None):
        calls.append((command, timeout, max_chars))
        return CommandResult(command=command, exit_code=2 if max_chars else 0,
                             stdout="TLS report" if max_chars else NMAP_SSH_ONLY, stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "run_command", recording)
    custom = {"tlsscan": CustomTool(name="tlsscan", program="sslscan", args=["--no-colour", "{target}"], scope="target",
                                    timeout_seconds=15, created_at=run.created_at),
              "hdrcheck": CustomTool(name="hdrcheck", program="curl", args=["-sI", "{url}"], scope="url",
                                     created_at=run.created_at)}
    live = execute_and_wait(RunManager(), ExecuteRequest(target="10.10.20.5", authorized=True),
                            [*ALL_TOOLS, "hdrcheck", "tlsscan"], budget=600, custom_tools=custom)
    assert live.status == "completed" and live.error is None
    assert (live.stages[3].status, live.stages[3].error) == ("skipped", "No reachable web services, nothing to scan.")
    assert (live.stages[4].status, live.stages[4].exit_code, live.stages[4].partial) == ("completed", 2, False)
    custom_calls = [call for call in calls if call[2] is not None]
    assert [call[0] for call in custom_calls] == [["/fake/bin/sslscan", "--no-colour", "10.10.20.5"]]
    assert custom_calls[0][1] == 15 and custom_calls[0][2] == STDOUT_CHARS  # the tool's own limit, not its share
    assert [o.stdout for o in live.custom_outputs] == ["TLS report"] and live.summary.risk_score == run.summary.risk_score
    assert (live.custom_outputs[0].ended, live.custom_outputs[0].exit_code) == ("exited", 2)  # the program's own code
    # The API documents when a stage has an exit code: Nmap's, or a target-scope custom tool's own.
    described = StageResult.model_fields["exit_code"].description
    assert "a custom tool that runs once on the target" in described and "stopped at its time limit" in described
    assert "printing too much or by the server shutdown" in described
    assert "Always null for the per-URL stages" in described
    # Custom tool output is never examined, so the clean-host highlight names the built-in tools that ran (WhatWeb and
    # Nikto were skipped) and says so; the run without custom tools keeps the old sentence (checked at the end).
    assert live.summary.highlights == ["No notable exposures were identified with Nmap; custom tool output is not "
                                       "examined."]

    # The live branch, call by call: time limits, output limits, programs that cannot run, the deadline margin.
    def live_stage(scope="target", args=("--no-colour", "{target}"), context=None, first="completed", result=None,
                   found=("/fake/bin/sslscan", None)):
        calls.clear()
        monkeypatch.setattr(hybrid, "find_program", lambda program: found)
        monkeypatch.setattr(hybrid, "run_command", lambda command, timeout, max_chars=None:
                            calls.append((command, timeout, max_chars)) or result(command))
        one = make_run(id="p3custom0001", target="10.10.20.5", status="running", mode="live", tools=["nmap", "tlsscan"],
                       stages=[StageResult(stage="port_scan", tool="nmap", status=first),
                               StageResult(stage="custom_tool", tool="tlsscan")])
        one.custom_tools["tlsscan"] = CustomTool(name="tlsscan", program="sslscan", args=list(args), scope=scope,
                                                 timeout_seconds=15, created_at=one.created_at)
        return one, run_stage_handler(hybrid.stage_custom_tool, one, context or {}, stage_index=1)

    def ok(command):
        return CommandResult(command=command, exit_code=0, stdout="ok", stderr="", duration_seconds=0.1)

    one, st = live_stage(result=lambda c: CommandResult(command=c, exit_code=None, stdout="part", stderr="",
                                                        duration_seconds=15, timed_out=True))
    assert (st.status, st.partial, st.exit_code) == ("completed", True, None) and "stopped at their time limit" in st.error
    assert (one.custom_outputs[0].exit_code, one.custom_outputs[0].timed_out) == (None, True)
    assert one.custom_outputs[0].ended == "time_limit"
    # Stopped for printing more than the limit: run_command reports no exit code, as a kill's status is not the tool's.
    one, st = live_stage(result=lambda c: CommandResult(command=c, exit_code=None, stdout="x", stderr="",
                                                        duration_seconds=1, truncated=True))
    assert st.partial and "printed more than 50,000 characters and were stopped" in st.error
    assert one.custom_outputs[0].truncated and not one.custom_outputs[0].timed_out
    assert (one.custom_outputs[0].ended, one.custom_outputs[0].exit_code, st.exit_code) == ("output_limit", None, None)
    # A program that had already exited by itself when its output passed the limit keeps its exit code, and the note
    # does not claim that HybridSec stopped it.
    one, st = live_stage(result=lambda c: CommandResult(command=c, exit_code=0, stdout="x", stderr="",
                                                        duration_seconds=1, truncated=True))
    assert (one.custom_outputs[0].ended, one.custom_outputs[0].exit_code, st.exit_code) == ("exited", 0, 0)
    assert (st.status, st.partial) == ("completed", True) and one.custom_outputs[0].truncated
    # Each stream is counted on its own, and the run-wide limit may have kept less of a call, hence "at most".
    assert st.error == ("1 call(s) printed more than 50,000 characters on standard output or on standard error, so at "
                        "most the first 50,000 characters of each were kept.")
    one, st = live_stage(result=lambda c: CommandResult(command=c, exit_code=127, stdout="",
                                                        stderr="Could not start sslscan: x", duration_seconds=0))
    assert st.status == "failed" and st.error.startswith("tlsscan could not run: 10.10.20.5: Could not start sslscan")
    assert (one.custom_outputs[0].ended, one.custom_outputs[0].exit_code) == ("exited", 127)  # it ran and said so
    # A process that could not be started at all has no exit code; outside a shutdown the stage fails as before.
    monkeypatch.setattr(hybrid, "is_shutting_down", lambda: False)

    def refused(command):
        raise OSError("the server is shutting down" if hybrid.is_shutting_down() else "[Errno 13] Permission denied")

    one, st = live_stage(result=refused)
    assert (st.status, st.exit_code) == ("failed", None)
    assert st.error == "tlsscan could not run: 10.10.20.5: Could not start sslscan: [Errno 13] Permission denied"
    assert (one.custom_outputs[0].ended, one.custom_outputs[0].exit_code) == ("not_started", None)
    # A shutdown that kills a running call keeps what it printed so far: the call ended with the shutdown (no exit
    # code), not "could not run", and the run is marked interrupted.
    context = {"deadline": time.monotonic() + 100}
    one, st = live_stage(context=context, result=lambda c: CommandResult(
        command=c, exit_code=1, stdout="started\n", stderr="", duration_seconds=2, interrupted=True))
    stopped = one.custom_outputs[0]
    assert (stopped.ended, stopped.exit_code, stopped.timed_out) == ("shutdown", None, False)
    assert stopped.stdout == "started\n"
    assert (st.status, st.partial, st.exit_code, context["interrupted"]) == ("completed", True, None, True)
    assert st.error == "1 call(s) were stopped because the server shut down, so their output is incomplete."
    _, st = live_stage(found=(None, None), result=ok)
    assert st.status == "failed" and "tlsscan is not installed" in st.error and calls == []
    _, st = live_stage(found=(None, "Program: sslscan resolves to /bin/bash. bash is a shell"), result=ok)
    assert st.status == "failed" and st.error.startswith("Program: sslscan resolves to") and calls == []
    _, st = live_stage(first="failed", result=ok)
    assert (st.status, st.error) == ("skipped", "The first stage failed, so tlsscan did not run.") and calls == []
    _, st = live_stage(context={"deadline": time.monotonic() + 14}, result=ok)  # 14 - DRAIN_SECONDS < 10
    assert st.status == "failed" and "time budget ran out" in st.error and calls == []
    # A stage the budget gave no time (it cannot leave a custom call its minimum after the built-in stages', see
    # _stage_budgets) runs only on time the built-in stages left over; with none left it starts nothing and names
    # the budget that would be enough: 38 s for Nmap and one custom tool.
    short, _ = live_stage(result=ok)
    short.stages[1] = StageResult(stage="custom_tool", tool="tlsscan")
    short.custom_outputs.clear()
    calls.clear()
    hybrid.stage_custom_tool(hybrid.manager, short, ExecuteRequest(target=short.target, authorized=True),
                             short.stages[1], {"deadline": time.monotonic() + 14}, 0.0)
    assert (short.stages[1].status, short.custom_outputs, calls) == ("failed", [], [])
    assert short.stages[1].error == ("The time budget ran out before tlsscan could run. Raise the run's timeout to "
                                     "at least 38 seconds.")
    ports = [PortFinding(host="10.10.20.5", port=80, service="http", is_web=True),
             PortFinding(host="10.10.20.5", port=8443, service="https", is_web=True)]
    _, st = live_stage(scope="url", args=("-sI", "{url}"), context={"web_ports": ports}, result=ok)
    assert [c[0] for c in calls] == [["/fake/bin/sslscan", "-sI", "http://10.10.20.5"],
                                     ["/fake/bin/sslscan", "-sI", "https://10.10.20.5:8443"]]
    assert all(c[1] == 15 and c[2] == STDOUT_CHARS for c in calls) and st.exit_code is None
    # A shutdown between per-URL calls: the call it stopped keeps its output, and the URLs after it are counted as
    # not started. A call that run_command refused because the shutdown had begun is counted with them.
    def in_turn(*fakes):
        """A result for live_stage that answers each call with the next of `fakes`."""
        pending = list(fakes)

        def answer(command):
            return pending.pop(0)(command)
        return answer

    three = [*ports, PortFinding(host="10.10.20.5", port=8080, service="http", is_web=True)]
    one, st = live_stage(scope="url", args=("-sI", "{url}"), context={"web_ports": three}, result=in_turn(
        ok, lambda c: CommandResult(command=c, exit_code=1, stdout="started\n", stderr="", duration_seconds=2,
                                    interrupted=True)))
    assert len(calls) == 2
    assert [(o.ended, o.exit_code) for o in one.custom_outputs] == [("exited", 0), ("shutdown", None)]
    assert (st.status, st.partial) == ("completed", True)
    assert st.error == ("1 call(s) were stopped because the server shut down, so their output is incomplete. "
                        "1 call(s) were not started because the server shut down.")
    monkeypatch.setattr(hybrid, "is_shutting_down", lambda: True)  # from here on run_command refuses new processes
    context = {"web_ports": three}
    one, st = live_stage(scope="url", args=("-sI", "{url}"), context=context, result=in_turn(ok, refused))
    assert len(calls) == 2 and context["interrupted"] is True
    assert (st.status, st.partial) == ("completed", True)
    assert st.error == "2 call(s) were not started because the server shut down."
    assert [(o.ended, o.exit_code) for o in one.custom_outputs] == [("exited", 0), ("not_started", None)]
    assert one.custom_outputs[1].stderr == "Could not start sslscan: the server is shutting down"
    # Refused before its first call, the stage ran nothing: it is skipped for the shutdown, not failed.
    one, st = live_stage(context={"deadline": time.monotonic() + 100}, result=refused)
    assert (st.status, st.error, st.exit_code) == ("skipped", hybrid.SHUTDOWN_REASON, None)
    assert [o.ended for o in one.custom_outputs] == ["not_started"]
    # The run-wide limit on custom output (RUN_OUTPUT_CHARS) is no longer silent: run_limit marks each call it cut or
    # left empty, and the stage says so in a note that does not make it partial (the tool itself was not cut short).
    six = [PortFinding(host="10.10.20.5", port=8000 + n, service="http", is_web=True) for n in range(6)]
    one, st = live_stage(scope="url", args=("-sI", "{url}"), context={"web_ports": six},
                         result=lambda c: CommandResult(command=c, exit_code=0, stdout="z" * 45000, stderr="",
                                                        duration_seconds=0))
    assert [len(o.stdout) for o in one.custom_outputs] == [45000] * 4 + [20000, 0]
    assert [o.run_limit for o in one.custom_outputs] == [False] * 4 + [True, True]
    assert [o.truncated for o in one.custom_outputs] == [False] * 4 + [True, True]
    assert (st.status, st.partial) == ("completed", False)
    assert st.error == ("1 call(s) kept only part of their output and 1 call(s) kept none of their output, because "
                        f"the run's custom-output limit ({RUN_OUTPUT_CHARS:,} characters) was reached.")
    one, _ = live_stage(result=lambda c: CommandResult(command=c, exit_code=0, stdout="\x1b[31m" + "y" * 60000,
                                                       stderr="e" * 6000, duration_seconds=0))
    kept = one.custom_outputs[0]
    assert kept.stdout == "y" * STDOUT_CHARS and len(kept.stderr) == 5000 and kept.truncated
    for _ in range(4):
        hybrid._keep_output(hybrid.manager, one, "tlsscan", "10.10.20.5",
                            CommandResult(command=["x"], exit_code=0, stdout="y" * 60000, stderr="", duration_seconds=0))
    assert sum(len(o.stdout) + len(o.stderr) for o in one.custom_outputs) == RUN_OUTPUT_CHARS
    assert one.custom_outputs[-1].stdout == "" and one.custom_outputs[-1].truncated  # nothing kept past the run cap
    # The first call was cut by the per-call limits only; the run-wide limit cut the fourth and emptied the fifth.
    assert [o.run_limit for o in one.custom_outputs] == [False, False, False, True, True]

    # The runner's per-call limit counts stdout and stderr separately: two streams of 30 characters stay under a
    # limit of 50 and are kept whole, while a stream that passes it is cut at 50 characters and the call is stopped
    # with no exit code (a program that had already exited keeps its own). The other stream is kept whole, so a tool
    # that writes a lot on standard error keeps its result. Popen and the kill are fakes here, so no process starts.
    class Pipe:
        encoding, errors = "utf-8", "replace"

        def __init__(self, text: str) -> None:
            self.buffer = io.BytesIO(text.encode("utf-8"))

    class Process:
        pid = 0

        def __init__(self, out: str, err: str, running: bool) -> None:
            self.stdout, self.stderr, self.running = Pipe(out), Pipe(err), running
            self.returncode = None if running else 3

        def poll(self):
            return None if self.running else self.returncode

        def wait(self, timeout=None):
            return self.returncode

    def kill(proc) -> None:
        if proc.running:
            proc.running, proc.returncode = False, 1  # the status a kill leaves on Windows

    def capped(out: str, err: str, running: bool) -> CommandResult:
        process = Process(out, err, running)
        with pytest.MonkeyPatch.context() as patched:
            patched.setattr(runner, "_shutting_down", False)
            patched.setattr(runner, "_kill", kill)
            patched.setattr(runner, "subprocess", SimpleNamespace(**{**vars(runner.subprocess),
                                                                     "Popen": lambda command, **kwargs: process}))
            return runner.run_command(["/fake/bin/sslscan"], timeout=5, max_chars=50)

    both = capped("o" * 30, "e" * 30, running=False)
    assert (both.stdout, both.stderr, both.truncated, both.exit_code) == ("o" * 30, "e" * 30, False, 3)
    noisy = capped("o" * 30, "e" * 60, running=True)
    assert (noisy.stdout, noisy.stderr) == ("o" * 30, "e" * 50)
    assert (noisy.truncated, noisy.exit_code, noisy.timed_out) == (True, None, False)
    flood = capped("o" * 60, "e" * 30, running=True)
    assert (flood.stdout, flood.stderr, flood.truncated, flood.exit_code) == ("o" * 50, "e" * 30, True, None)
    exited = capped("o" * 30, "e" * 60, running=False)
    assert (exited.stdout, exited.stderr, exited.truncated, exited.exit_code) == ("o" * 30, "e" * 50, True, 3)
    quiet = capped("line 1\r\nline 2\n", "warn", running=False)  # decoded as a text-mode pipe would, newlines too
    assert (quiet.stdout, quiet.stderr, quiet.truncated, quiet.exit_code) == ("line 1\nline 2\n", "warn", False, 3)
    assert runner._live == set()
    assert [p.port for p in run.ports] == [22] and run.web == [] and run.vulns == []
    assert run.summary.open_ports == 1 and run.summary.hosts_up == 1
    assert run.summary.highlights == ["No notable exposures were identified with the selected tools."]


def test_quiet_host_with_no_open_ports_completes_with_a_caveat(monkeypatch):
    """Nmap finishing with no host up is a valid "nothing open" answer: the stage completes with a note."""
    fake_scanner(monkeypatch, stdout=NMAP_NO_HOSTS)
    run = execute_and_wait(RunManager(), ExecuteRequest(target="10.10.20.5", authorized=True), ["nmap", "whatweb"])
    assert run.status == "completed" and run.ports == []
    assert run.stages[0].status == "completed"
    assert "Host appears down or fully filtered" in run.stages[0].error
    assert run.stages[1].status == "skipped"
    assert run.summary.highlights == ["No open ports were found in the probed range."]


def test_crashing_stage_fails_only_itself_and_the_next_stage_still_runs(monkeypatch):
    """An exception inside one stage handler fails that stage; the run continues and still completes."""
    def broken_handler(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setitem(hybrid.STAGE_HANDLERS, "web_fingerprint", broken_handler)
    run = execute_and_wait(RunManager(), ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True),
                           list(ALL_TOOLS))
    assert [s.status for s in run.stages] == ["simulated", "failed", "simulated"]
    assert run.stages[1].error == "RuntimeError: boom"
    assert run.status == "completed" and run.error == "whatweb: RuntimeError: boom"
    assert run.vulns and any("whatweb crashed: RuntimeError: boom" in line for line in run.log)

    # A crash outside the handlers (here a failed save after the Nmap stage) fails the run, closes the stages that
    # never ran with the error instead of leaving them "pending", and still counts what Nmap found.
    class FlakyStore(RunManager):
        saves = 0

        def _persist(self, run):
            FlakyStore.saves += 1
            if FlakyStore.saves == 3:  # the save right after the Nmap stage
                raise OSError("disk I/O error")
            super()._persist(run)

    monkeypatch.undo()
    run = execute_and_wait(FlakyStore(), ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True),
                           list(ALL_TOOLS))
    assert run.status == "failed" and run.error == "OSError: disk I/O error"
    assert [s.status for s in run.stages] == ["simulated", "failed", "failed"]
    assert run.stages[2].error == "OSError: disk I/O error"
    assert run.summary.open_ports == len(run.ports) > 0 and run.summary.hosts_up == 1
    assert any("pipeline error: OSError: disk I/O error" in line for line in run.log)


def test_run_manager_refuses_a_run_beyond_the_concurrency_cap(monkeypatch):
    """With every slot taken, create() raises RunLimitExceeded and registers nothing new."""
    manager = RunManager()
    monkeypatch.setattr(settings, "max_concurrent_runs", 1)
    busy = make_run(id="busy00000001", status="running")
    manager._active[busy.id] = busy
    with pytest.raises(RunLimitExceeded, match=r"1 run\(s\) are already executing \(the limit is 1\)"):
        manager.create(ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True), "127.0.0.1", ["nmap"],
                       None, 30)
    assert set(manager._active) == {busy.id}
    # After the operator lowers the cap while runs execute, the message counts the runs really executing.
    manager._active["busy00000002"] = make_run(id="busy00000002", status="running")
    with pytest.raises(RunLimitExceeded, match=r"^2 run\(s\) are already executing \(the limit is 1\)"):
        manager.create(ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True), "127.0.0.1", ["nmap"],
                       None, 30)
    del manager._active["busy00000002"]
    assert manager.is_active(busy.id) is True and manager.is_active("unknown00000") is False


def test_run_manager_frees_the_slot_when_the_run_cannot_be_saved(monkeypatch):
    """A run that cannot be written to the database is not started and gives its concurrency slot back."""
    assert wait_for(lambda: not hybrid.manager._active), "earlier runs are still executing"

    def refuse(run):
        raise OSError("database is read-only (simulated)")

    monkeypatch.setattr(hybrid.storage, "save_run", refuse)
    manager = RunManager()
    with pytest.raises(OSError):
        manager.create(ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True), "127.0.0.1", ["nmap"],
                       None, 30)
    assert manager._active == {}
    monkeypatch.undo()

    # A worker thread that cannot start also gives the slot back, and the stored run says why instead of
    # staying "queued" forever (it would count against the cap and refuse deletion until a restart).
    def no_thread(self):
        raise RuntimeError("can't start new thread")

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(hybrid.threading.Thread, "start", no_thread)
        with pytest.raises(RuntimeError, match="can't start new thread"):
            manager.create(ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True, label="no-thread-run"),
                           "127.0.0.1", ["nmap"], None, 30)
    assert manager._active == {}
    stored = next(storage.get_run(i.id) for i in storage.list_runs(limit=50) if i.label == "no-thread-run")
    storage.delete_run(stored.id)
    assert stored.status == "failed" and stored.error == "The server could not start this run: can't start new thread"
    assert [s.status for s in stored.stages] == ["skipped"]


def test_live_view_of_a_running_run_is_an_independent_copy():
    """Readers get a deep copy of an executing run, so they can never change the worker's live object."""
    manager = RunManager()
    live = make_run(id="live00000001", status="running", log=["queued"])
    manager._active[live.id] = live
    snapshot = manager.get(live.id)
    assert snapshot == live and snapshot is not live
    snapshot.log.append("changed by a reader")
    assert live.log == ["queued"]
    assert manager.get("missing00000") is None


def test_queued_run_interrupted_by_a_restart_is_failed_on_startup():
    """A run still queued when the server stopped is failed at the next startup, stages included."""
    queued = make_run(id="stuckqueued1", status="queued", tools=["nmap", "whatweb"],
                      stages=[StageResult(stage="port_scan", tool="nmap"),
                              StageResult(stage="web_fingerprint", tool="whatweb")])
    finished = make_run(id="stuckdone001", status="completed")
    storage.save_run(queued)
    storage.save_run(finished)
    try:
        with TestClient(app, base_url="http://localhost") as client:  # the app's startup runs fail_stale_runs()
            recovered = client.get(f"/api/runs/{queued.id}").json()
        assert recovered["status"] == "failed" and "restarted" in recovered["error"]
        assert [s["status"] for s in recovered["stages"]] == ["failed", "failed"]
        assert all("restarted" in s["error"] for s in recovered["stages"])
        assert recovered["finished_at"] is not None and recovered["duration_seconds"] is None  # it never started
        assert "restarted" in recovered["log"][-1]
        assert storage.get_run(finished.id).status == "completed"  # finished runs are left alone
    finally:
        storage.delete_run(queued.id)
        storage.delete_run(finished.id)


# --- Time budget and stage helpers -----------------------------------------------------------------

@pytest.mark.parametrize("tools,total,expected", [
    (["nmap", "whatweb", "nikto"], 1000, {"nmap": 550.0, "whatweb": 200.0, "nikto": 250.0}),
    (["nmap", "whatweb"], 300, {"nmap": 220.0, "whatweb": 80.0}),
    (["whatweb", "nikto"], 900, {"whatweb": 400.0, "nikto": 500.0}),
    (["nmap"], 120, {"nmap": 120.0}),
])
def test_stage_budgets_follow_the_stage_weights(tools, total, expected):
    """Shares are 55 % Nmap, 20 % WhatWeb and 25 % Nikto, rescaled over the tools that are actually in the run."""
    assert _stage_budgets(tools, total) == pytest.approx(expected)


def test_stage_budgets_lift_a_short_share_from_the_stage_with_the_most_slack():
    """At 60 s Nikto's 15 s share is lifted to its 20 s minimum and the 5 s come from Nmap, not from WhatWeb."""
    assert _stage_budgets(["nmap", "whatweb", "nikto"], 60) == pytest.approx({"nmap": 28.0, "whatweb": 12.0,
                                                                              "nikto": 20.0})


@pytest.mark.parametrize("total", [40, 45, 60, 80, 100, 180, 900])
def test_stage_budgets_never_exceed_the_total_when_the_minimums_fit(total):
    """Whenever the budget can cover every stage minimum, the shares add up to at most the budget."""
    shares = _stage_budgets(["nmap", "whatweb", "nikto"], total)
    assert sum(shares.values()) <= total + 1e-6
    assert all(shares[t] >= STAGE_MIN_SECONDS[t] for t in shares)


@pytest.mark.parametrize("total", [0, 1, 10, 30])
def test_stage_budgets_stay_at_the_minimums_for_a_tiny_total(total):
    """A budget too small for the minimums still yields non-negative shares, each at least its tool's minimum."""
    shares = _stage_budgets(["nmap", "whatweb", "nikto"], total)
    assert all(share >= 0 for share in shares.values())
    assert all(shares[t] >= STAGE_MIN_SECONDS[t] for t in shares)
    if total <= 10:
        assert shares == STAGE_MIN_SECONDS


def test_stage_budgets_give_an_unlisted_tool_the_default_share():
    """A future tool without an entry in STAGE_TIME_WEIGHTS gets the default weight 0.2 and minimum 10 s."""
    assert _stage_budgets(["nmap", "dnsx"], 150) == pytest.approx({"nmap": 110.0, "dnsx": 40.0})
    # Several such tools (custom tools) share that one weight, so they take a bounded share from the built-in tools.
    assert _stage_budgets(["nmap", "a", "b"], 150) == pytest.approx({"nmap": 110.0, "a": 20.0, "b": 20.0})
    # Lifting many custom tools to their 10 s minimum never takes that time from the built-in stage.
    many = _stage_budgets(["nmap", *(f"c{i}" for i in range(10))], 120)
    assert many["nmap"] == pytest.approx(88.0) and all(many[f"c{i}"] == 10.0 for i in range(10))
    # A budget that cannot leave a custom tool its 10 s minimum after the built-in stages' minimums (40 s for the
    # three of them, 10 s for Nmap alone) gives the custom stages no share and the built-in stages exactly the shares
    # they would have without custom tools: a custom call then runs only on time the built-in stages leave over.
    for total in (0, 30, 40, 45, 49):
        shares, alone = _stage_budgets([*ALL_TOOLS, "hdrcheck"], total), _stage_budgets(ALL_TOOLS, total)
        assert shares == pytest.approx({**alone, "hdrcheck": 0.0}), total
        assert (shares["whatweb"], shares["nikto"]) == pytest.approx((10.0, 20.0)) and shares["nmap"] >= 10.0, total
    assert _stage_budgets(["nmap", "a", "b"], 19) == pytest.approx({"nmap": 19.0, "a": 0.0, "b": 0.0})
    # With none left, a custom stage names the budget that would be enough: the built-in minimums plus 10 s per tool, or
    # the budget whose proportional share (weight 0.2) gives each custom tool its 10 s, whichever is larger. At that
    # budget every custom tool gets its minimum.
    for tools, enough in (([*ALL_TOOLS, "hdrcheck"], 60), (["nmap", "hdrcheck"], 38), (["nmap", "nikto", "a"], 50),
                          ([*ALL_TOOLS, "a", "b"], 120), (["whatweb", "a"], 20)):
        assert hybrid._custom_budget_needed(tools) == enough, tools
        shares = _stage_budgets(tools, enough)
        assert all(shares[t] >= 10.0 for t in tools if t not in STAGE_MIN_SECONDS), tools
    # When every share is above its minimum nothing changes: the custom tool's weight of 0.2 is rescaled with the rest.
    assert _stage_budgets([*ALL_TOOLS, "hdrcheck"], 120) == pytest.approx({"nmap": 55.0, "whatweb": 20.0, "nikto": 25.0,
                                                                          "hdrcheck": 20.0})
    assert _stage_budgets([*ALL_TOOLS, "hdrcheck"], 1200) == pytest.approx({"nmap": 550.0, "whatweb": 200.0,
                                                                           "nikto": 250.0, "hdrcheck": 200.0})


@pytest.mark.parametrize("stage_timeout,url_count,minimum,expected", [
    (100.0, 4, 10.0, 25.0),   # an equal share of the stage budget per URL
    (100.0, 20, 10.0, 10.0),  # never below the minimum a probe needs
    (100.0, 1, 10.0, 100.0),  # one URL may use the whole stage budget
    (5.0, 1, 10.0, None),     # a stage budget below the minimum starts nothing
])
def test_time_for_next_url_shares_the_stage_budget_with_a_floor(stage_timeout, url_count, minimum, expected):
    """Each URL gets an equal share of the stage budget, never less than the minimum, or None if that is impossible."""
    # Exactly: the few microseconds between two clock readings never cut a whole share short (29.99999 s).
    assert _time_for_next_url({}, _stage_end({}, stage_timeout), stage_timeout, url_count, minimum) == expected


def test_time_for_next_url_is_capped_by_the_run_deadline():
    """The run-wide deadline wins over the stage budget, and too little time left means no further URL. The end
    of the stage's slot caps it too: a stage may use time an earlier stage left over but never a later stage's
    share, and a stage that starts late keeps its whole share."""
    later = time.monotonic() + 1000
    soon = {"deadline": time.monotonic() + 30}
    assert _time_for_next_url(soon, later, 100.0, 1, 10.0) == pytest.approx(30.0, abs=1.0)
    assert _time_for_next_url({"deadline": time.monotonic() + 5}, later, 100.0, 1, 10.0) is None
    # The time left in the stage caps the next URL, and a URL that no longer fits is not started.
    assert _time_for_next_url({}, time.monotonic() + 15, 36.0, 3, 10.0) == 12.0
    assert _time_for_next_url({}, time.monotonic() + 11, 36.0, 3, 10.0) == 11
    assert _time_for_next_url({}, time.monotonic() + 6, 36.0, 8, 10.0) is None
    # The time left is rounded down, never up: 19.6 s cannot start a URL that needs 20 s.
    assert _time_for_next_url({"deadline": time.monotonic() + 19.6}, later, 100.0, 1, 20.0) is None
    now = time.monotonic()
    assert _stage_end({}, 36.0) == pytest.approx(now + 36.0, abs=0.5)                    # no slots: its share from now
    assert _stage_end({"slot_end": now + 90}, 36.0) == pytest.approx(now + 90, abs=0.5)   # time an earlier stage left
    assert _stage_end({"slot_end": now - 5}, 36.0) == pytest.approx(now + 36.0, abs=0.5)  # started late: whole share


def test_web_targets_assume_the_standard_ports_without_a_port_scan():
    """Without an Nmap stage the web stages probe 80 and 443 on the target; with one they use what Nmap found."""
    no_scan = make_run(tools=["whatweb"], stages=[StageResult(stage="web_fingerprint", tool="whatweb")])
    assumed = _web_targets(no_scan, {})
    assert [(p.host, p.port, p.service, p.is_web) for p in assumed] == [("127.0.0.1", 80, "http", True),
                                                                        ("127.0.0.1", 443, "https", True)]
    with_scan = make_run(tools=["nmap", "whatweb"], stages=[StageResult(stage="port_scan", tool="nmap"),
                                                             StageResult(stage="web_fingerprint", tool="whatweb")])
    assert _web_targets(with_scan, {"web_ports": []}) == []
    found = [PortFinding(host="127.0.0.1", port=8080, service="http", is_web=True)]
    assert _web_targets(with_scan, {"web_ports": found}) == found


def test_top_ports_is_capped_by_the_server_maximum(monkeypatch):
    """A request for more ports than the server allows is silently capped at the configured maximum."""
    monkeypatch.setattr(settings, "max_top_ports", 250)
    run = make_run(id="cap000000001", mode="simulated", status="running",
                   stages=[StageResult(stage="port_scan", tool="nmap")])
    request = ExecuteRequest(target=run.target, authorized=True, top_ports=65535, simulate=True)
    hybrid.stage_port_scan(hybrid.manager, run, request, run.stages[0], {}, 30.0)
    assert "--top-ports 250 " in run.stages[0].command and run.stages[0].status == "simulated"


def test_port_scan_hands_at_most_twelve_web_services_to_the_web_stages(monkeypatch):
    """Of 15 open web ports only the first 12 are passed on, and the run log says so."""
    ports_xml = "".join(f'<port protocol="tcp" portid="{8000 + i}"><state state="open"/><service name="http"/></port>'
                        for i in range(15))
    fake_scanner(monkeypatch, stdout=NMAP_HEAD + '<host><status state="up"/><address addr="10.10.20.5" '
                                                 f'addrtype="ipv4"/><ports>{ports_xml}</ports></host></nmaprun>')
    run = three_stage_run()
    context: dict = {}
    run_stage_handler(hybrid.stage_port_scan, run, context)
    assert len(run.ports) == 15 and len(context["web_ports"]) == MAX_WEB_TARGETS == 12
    assert [p.port for p in context["web_ports"]] == list(range(8000, 8012))
    assert any(f"limiting web stages to the first {MAX_WEB_TARGETS} of 15 web services" in line for line in run.log)
    # The three services that were never probed make both web stages partial, with a note, so the run never
    # reads as a complete scan. (The web stages are simulated here; the cap applies the same way.)
    assert context["web_dropped"] == 3
    run.mode = "simulated"
    whatweb = run_stage_handler(hybrid.stage_web_fingerprint, run, context, stage_index=1)
    nikto = run_stage_handler(hybrid.stage_web_vuln_scan, run, context, stage_index=2)
    for stage in (whatweb, nikto):
        assert stage.partial is True
        assert stage.error == f"3 web service(s) beyond the limit of {MAX_WEB_TARGETS} per run were not probed."
    assert hybrid.summarize(run).partial is True
    # The simulated Nikto command shows the per-URL -maxtime a live run would pass (30 s / 12 URLs, at least 20 s).
    assert "-maxtime 20s " in nikto.command


def test_nikto_only_scans_urls_that_answered_whatweb():
    """A web service that gave WhatWeb no HTTP response is left out of the Nikto stage."""
    ports = [PortFinding(host="10.10.20.5", port=80, service="http", product="nginx", is_web=True),
             PortFinding(host="10.10.20.5", port=8080, service="http", product="Apache Tomcat", is_web=True)]
    context = {"web_ports": ports,
               "web": [WebFinding(url="http://10.10.20.5", host="10.10.20.5", port=80, reachable=False),
                       WebFinding(url="http://10.10.20.5:8080", host="10.10.20.5", port=8080, reachable=True)]}
    run = three_stage_run(mode="simulated")
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, context, stage_index=2)
    assert stage.status == "simulated" and run.vulns
    assert all(v.url.startswith("http://10.10.20.5:8080") for v in run.vulns)
    # A custom tool that runs per URL probes exactly the URLs Nikto scans.
    run.tools.append("hdrcheck")
    run.stages.append(StageResult(stage="custom_tool", tool="hdrcheck"))
    run.custom_tools["hdrcheck"] = CustomTool(name="hdrcheck", program="curl", args=["-sI", "{url}"], scope="url",
                                              created_at=run.created_at)
    custom_stage = run_stage_handler(hybrid.stage_custom_tool, run, context, stage_index=3)
    assert custom_stage.status == "simulated" and [o.target for o in run.custom_outputs] == ["http://10.10.20.5:8080"]


def test_nikto_is_skipped_when_no_url_answered_whatweb():
    """When every web service was unreachable for WhatWeb, Nikto is skipped with a reason instead of running."""
    ports = [PortFinding(host="10.10.20.5", port=80, service="http", is_web=True)]
    context = {"web_ports": ports,
               "web": [WebFinding(url="http://10.10.20.5", host="10.10.20.5", port=80, reachable=False)]}
    run = three_stage_run(mode="simulated")
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, context, stage_index=2)
    assert stage.status == "skipped" and stage.error == "No reachable web services, nothing to scan."
    assert run.vulns == []
    # A per-URL custom tool is skipped the same way.
    run.tools.append("hdrcheck")
    run.stages.append(StageResult(stage="custom_tool", tool="hdrcheck"))
    run.custom_tools["hdrcheck"] = CustomTool(name="hdrcheck", program="curl", args=["-sI", "{url}"], scope="url",
                                              created_at=run.created_at)
    custom_stage = run_stage_handler(hybrid.stage_custom_tool, run, context, stage_index=3)
    assert custom_stage.status == "skipped" and custom_stage.error == "No reachable web services, nothing to scan."
    assert run.custom_outputs == []


@pytest.mark.parametrize("statuses,errors,expected", [
    ([], [], ("completed", None)),
    (["completed", "completed", "completed"], [None, None, None], ("completed", None)),
    (["failed", "skipped", "skipped"], ["nmap died", None, None], ("failed", "nmap died")),
    (["completed", "failed", "completed"], [None, "no answer", None], ("completed", "whatweb: no answer")),
    (["completed", "failed", "failed"], [None, "a", "b"], ("completed", "whatweb: a; nikto: b")),
], ids=["no-stages", "all-ok", "first-failed", "middle-failed", "two-later-failed"])
def test_final_outcome_depends_only_on_the_first_stage(statuses, errors, expected):
    """Only a failed first stage fails the run; later failures leave it completed and are listed in its error."""
    stages = [StageResult(stage=TOOLS[t].stage, tool=t, status=s, error=e)
              for t, s, e in zip(ALL_TOOLS[:len(statuses)], statuses, errors, strict=True)]
    assert _final_outcome(stages) == expected


@pytest.mark.parametrize("mode,target,expected", [
    ("live", "lab.example.edu", "lab.example.edu"),
    ("live", "10.10.20.5", None),
    ("live", "10.10.20.0/24", None),
    ("live", "::1", None),
    ("simulated", "lab.example.edu", None),
])
def test_probe_host_returns_the_hostname_only_for_live_hostname_targets(mode, target, expected):
    """Probe URLs carry the operator's hostname only for a live run on a DNS name; addresses, ranges and
    simulated runs use the scanned address."""
    assert _probe_host(make_run(mode=mode, target=target)) == expected


# --- Summary, risk score and highlights -----------------------------------------------------------

def test_risk_score_is_zero_for_an_empty_run_and_never_above_100():
    """Nothing found scores 0; the four capped signals together can reach exactly 100 and no more."""
    assert _risk_score(make_run(), []) == 0
    maximal = make_run(
        ports=[port(n, "x") for n in range(1, 12)],
        web=[web(f"http://10.10.20.5:{n}", [{"name": "PHP", "version": str(i)} for i in range(3)], port=n)
             for n in range(8000, 8005)],
        vulns=[vuln("critical", f"c{i}") for i in range(3)],
    )
    assert summarize(maximal).risk_score == 100


def test_each_risk_signal_is_capped():
    """Ports stop counting at 30 points, web services at 20, disclosed versions at 20 and findings at 30."""
    assert _risk_score(make_run(ports=[port(n, "x") for n in range(1, 12)]), []) == 30  # 11 ports, 3 each
    five_services = [web(f"http://h:{n}", [], port=n) for n in range(5)]
    assert _risk_score(make_run(web=five_services), five_services) == 20  # 5 services, 5 each
    versions = [web("http://h", [{"name": f"t{i}", "version": "1"} for i in range(11)])]
    assert _risk_score(make_run(web=versions), versions) == 5 + 20  # one service plus 11 versions, 2 each
    assert _risk_score(make_run(vulns=[vuln("critical", f"c{i}") for i in range(3)]), []) == 30  # 45 capped


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_risk_points_per_finding_follow_the_severity_weights(severity):
    """A single finding adds exactly its severity weight: 0, 2, 5, 10 or 15 points."""
    assert _risk_score(make_run(vulns=[vuln(severity, "x")]), []) == SEVERITY_WEIGHT[severity]


def test_risk_score_never_decreases_when_more_severe_findings_are_added():
    """Adding findings of increasing severity can only raise the score, until the findings cap of 30."""
    run = make_run(tools=["nikto"])
    previous = _risk_score(run, [])
    for severity in ["info", "low", "medium", "high", "critical", "critical", "critical"]:
        run.vulns.append(vuln(severity, f"finding {len(run.vulns)}"))
        score = _risk_score(run, [])
        assert score >= previous
        previous = score
    assert previous == 30


def test_unknown_severity_and_unreachable_services_add_no_risk():
    """A finding with an unexpected severity word and a service that never answered contribute 0 points."""
    assert _risk_score(make_run(vulns=[vuln("a|b", "odd")]), []) == 0
    silent = make_run(web=[web("http://10.10.20.5", [{"name": "nginx", "version": "1.18.0"}], reachable=False)])
    assert summarize(silent).risk_score == 0 and summarize(silent).web_services == 0


def test_highlights_rank_findings_by_severity_and_ignore_low_and_info():
    """Critical comes before high before medium, and low or info findings are never highlighted."""
    run = make_run(tools=["nikto"], vulns=[vuln("low", "L"), vuln("info", "I"), vuln("medium", "M"),
                                            vuln("critical", "C"), vuln("high", "H")])
    assert [h for h in _highlights(run, []) if h.startswith("[")] == ["[critical] C", "[high] H", "[medium] M"]


def test_highlights_list_at_most_three_findings():
    """Even with five distinct high findings, only the first three are highlighted."""
    run = make_run(tools=["nikto"], vulns=[vuln("high", f"H{i}") for i in range(5)])
    assert [h for h in _highlights(run, []) if h.startswith("[")] == ["[high] H0", "[high] H1", "[high] H2"]


def test_highlights_flag_at_most_four_risky_services_including_tls_wrapped_ones():
    """Remote-admin and database services are flagged (a TLS-wrapped mysql counts), at most four of them."""
    run = make_run(ports=[port(21, "ftp"), port(3306, "ssl/mysql"), port(23, "telnet"), port(6379, "redis"),
                          port(161, "snmp"), port(5900, "vnc"), port(22, "ssh")])
    exposed = [h for h in _highlights(run, []) if h.startswith("Management or database service exposed")]
    assert len(exposed) == 4
    assert "Management or database service exposed: ssl/mysql on port 3306" in exposed
    assert not any("ssh" in h for h in exposed)


def test_highlights_report_each_disclosed_version_once_and_only_for_sensitive_products():
    """nginx 1.18.0 seen on two URLs is one highlight; Bootstrap versions and unreachable services are ignored."""
    run = make_run(web=[web("http://10.10.20.5", [{"name": "nginx", "version": "1.18.0"},
                                                  {"name": "Bootstrap", "version": "4.6.0"}]),
                        web("https://10.10.20.5", [{"name": "NGINX", "version": "1.18.0"}], port=443),
                        web("http://10.10.20.5:8080", [{"name": "PHP", "version": "7.4"}], reachable=False, port=8080)])
    disclosed = [h for h in summarize(run).highlights if "disclosed" in h]
    assert disclosed == ["nginx 1.18.0 disclosed at http://10.10.20.5"]


@pytest.mark.parametrize("fields,expected", [
    ({"ports": [port(22, "ssh")]}, "No notable exposures were identified with the selected tools."),
    ({"stages": [StageResult(stage="port_scan", tool="nmap", status="completed")]},
     "No open ports were found in the probed range."),
    ({"tools": ["whatweb"], "stages": [StageResult(stage="web_fingerprint", tool="whatweb", status="failed",
                                                   error=hybrid.WHATWEB_NO_RESPONSE + ": http://10.10.20.5: no "
                                                         "HTTP response (exit 1)")]},
     "No reachable web service was found on the standard ports (no port scan in this workflow)."),
], ids=["nothing-notable", "no-ports-after-scan", "no-web-without-scan"])
def test_highlights_fallback_message_depends_on_the_workflow(fields, expected):
    """With nothing to highlight, the single message explains what was (not) found for that workflow."""
    assert summarize(make_run(**fields)).highlights == [expected]


def test_summary_caps_highlights_at_eight():
    """Three findings, four risky services and three versions would be ten highlights; the summary keeps eight."""
    run = make_run(
        ports=[port(21, "ftp"), port(23, "telnet"), port(3306, "mysql"), port(5432, "postgresql"), port(6379, "redis")],
        web=[web("http://10.10.20.5", [{"name": "nginx", "version": "1.18.0"}, {"name": "PHP", "version": "7.4.33"},
                                        {"name": "WordPress", "version": "5.8.2"}])],
        vulns=[vuln("high", f"H{i}") for i in range(3)],
    )
    highlights = summarize(run).highlights
    assert len(highlights) == 8 and len(_highlights(run, run.web)) == 10
    assert highlights[0] == "[high] H0"


def test_summary_counts_only_reachable_web_services_and_never_fewer_hosts_than_seen():
    """Unreachable URLs do not count as services or technologies, and hosts_up is at least the hosts with ports."""
    run = make_run(
        ports=[PortFinding(host="10.10.20.5", port=80, service="http"),
               PortFinding(host="lab.example.edu (10.10.20.6)", port=22, service="ssh")],
        web=[web("http://10.10.20.5", [{"name": "nginx"}, {"name": "PHP"}]),
             web("http://10.10.20.6", [{"name": "Apache"}], reachable=False)],
    )
    summary = summarize(run, hosts_up=0)
    assert summary.web_services == 1 and summary.technologies == 2
    assert summary.hosts_up == 2 and summary.open_ports == 2
    # Without a port scan a host that answered a web probe, or that carries a Nikto finding, is up: the
    # summary must not show "Hosts up 0" beside the web services that answered.
    web_only = make_run(tools=["whatweb"], web=[web("http://10.10.20.5", [{"name": "nginx"}])])
    assert summarize(web_only).hosts_up == 1 and summarize(web_only).web_services == 1
    unanswered = make_run(tools=["whatweb"], web=[web("http://10.10.20.5", [], reachable=False)])
    assert summarize(unanswered).hosts_up == 0
    nikto_only = make_run(tools=["nikto"], vulns=[vuln("low", "The X-Content-Type-Options header is not set.")])
    assert summarize(nikto_only).hosts_up == 1
    # A Nikto-only run is counted from its stage, never by splitting finding URLs (a damaged URL crashed the
    # summary and failed a completed scan), and a clean Nikto examination is a host that answered.
    damaged = make_run(tools=["nikto"], vulns=[VulnFinding(url="http://[::1", severity="info", description="Odd.")])
    assert summarize(damaged).hosts_up == 1
    examined = make_run(tools=["nikto"], stages=[StageResult(stage="web_vuln_scan", tool="nikto", status="completed")])
    assert summarize(examined).hosts_up == 1
    assert summarize(examined).highlights == ["No notable exposures were identified with the selected tools."]
    # With a custom tool in the run the sentence names the built-in tools whose stage ran (a failed or skipped one is
    # not named) and says that custom tool output is not examined.
    custom_stage = StageResult(stage="custom_tool", tool="hdrcheck", status="completed")
    examined.stages.append(custom_stage)
    assert summarize(examined).highlights == ["No notable exposures were identified with Nikto; custom tool output is "
                                              "not examined."]
    stages = [StageResult(stage="port_scan", tool="nmap", status="completed"),
              StageResult(stage="web_fingerprint", tool="whatweb", status="completed"),
              StageResult(stage="web_vuln_scan", tool="nikto", status="completed"), custom_stage]
    assert summarize(make_run(ports=[port(22, "ssh")], stages=stages)).highlights == [
        "No notable exposures were identified with Nmap, WhatWeb and Nikto; custom tool output is not examined."]
    stages[1] = StageResult(stage="web_fingerprint", tool="whatweb", status="failed", error="WhatWeb is not installed.")
    assert summarize(make_run(ports=[port(22, "ssh")], stages=stages)).highlights == [
        "No notable exposures were identified with Nmap and Nikto; custom tool output is not examined."]
    assert summarize(make_run(ports=[port(22, "ssh")], stages=[custom_stage])).highlights == [
        "No notable exposures were identified with the built-in tools; custom tool output is not examined."]
    # A port scan that failed, or a web probe that could not run, established nothing: no clean-host highlight.
    failed_scan = make_run(stages=[StageResult(stage="port_scan", tool="nmap", status="failed", error="nmap: boom")])
    assert summarize(failed_scan).highlights == []
    not_probed = make_run(tools=["whatweb"], stages=[StageResult(stage="web_fingerprint", tool="whatweb",
                                                               status="failed", error="WhatWeb is not installed.")])
    assert summarize(not_probed).highlights == []
    # One URL refused and the other could not be probed: that proves nothing about the standard ports.
    mixed = make_run(tools=["whatweb"], stages=[StageResult(
        stage="web_fingerprint", tool="whatweb", status="failed",
        error=hybrid.WHATWEB_NO_RESPONSE + " it probed: http://10.10.20.5: no HTTP response (exit 1); not probed: "
                                           "https://10.10.20.5: Could not start whatweb")])
    assert summarize(mixed).highlights == []
    # A run that ended as failed although its first stage completed (the server shut down or restarted) is
    # neither partial nor given a highlight that reads as a clean result.
    stopped = make_run(ports=[port(80, "http")], stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                                                        StageResult(stage="web_fingerprint", tool="whatweb",
                                                                    status="failed", error="stopped")])
    assert summarize(stopped).partial is True
    assert summarize(stopped, failed=True).partial is False and summarize(stopped, failed=True).highlights == []
    # A Nikto-only run whose budget ran out before any URL fails its stage, so it counts no host.
    nothing = make_run(tools=["nikto"], stages=[StageResult(stage="web_vuln_scan", tool="nikto", status="failed",
                                                            error="The time budget ran out before ...")])
    assert summarize(nothing).hosts_up == 0


# --- Planner: rules engine ------------------------------------------------------------------------

COMBOS = [list(c) for n in (1, 2, 3) for c in combinations(ALL_TOOLS, n)]


def plan_request(tools: list[str] | None = None, **fields) -> PlanRequest:
    values = {"tools": tools or ["nmap", "whatweb"], "objective": OBJECTIVE}
    values.update(fields)
    return PlanRequest(**values)


@pytest.mark.parametrize("tools", COMBOS, ids="+".join)
def test_rules_plan_covers_every_tool_combination(tools):
    """For any tool selection the rules planner orders the steps as the pipeline does, uses the real
    commands, requires authorization and fills every safety and limitation list."""
    plan = rules_plan(plan_request(list(reversed(tools))))
    assert [s.tool for s in plan.workflow] == tools
    assert [s.order for s in plan.workflow] == list(range(1, len(tools) + 1))
    assert [s.stage for s in plan.workflow] == [TOOLS[t].stage for t in tools]
    assert [s.command_template for s in plan.workflow] == [EXECUTOR_COMMANDS[t] for t in tools]
    assert all(s.purpose and s.inputs and s.outputs for s in plan.workflow)
    controls = plan.safety_controls
    assert controls.authorization_required is True
    assert controls.scope_restrictions and controls.rate_limits and controls.data_handling
    assert plan.limitations and plan.inputs and plan.outputs and plan.summary
    # The steps and the summary describe this workflow as the pipeline runs it: without a port scan the web
    # stages probe the target's standard ports (hybrid._web_targets), and a single tool has no later stages.
    assert all("previous step" not in text for s in plan.workflow for text in s.inputs)
    if "nmap" in tools:
        assert "attack surface" in plan.summary and "standard web ports" not in plan.summary
    else:
        assert "standard web ports 80 and 443" in plan.summary
        assert "standard web ports 80 and 443" in plan.workflow[0].inputs[0]
    if len(tools) == 1:
        assert plan.summary.startswith("An assessment tool that runs") and "later stage" not in plan.summary
    else:
        assert plan.summary.startswith("A hybrid assessment tool that chains") and "each later stage" in plan.summary
    if "nikto" in tools and "whatweb" in tools:
        assert "answered the fingerprint stage" in plan.workflow[-1].inputs[0]
    # The plan-level lists describe only the tools this workflow runs.
    assert ("number of top ports to probe" in plan.inputs) == ("nmap" in tools)
    assert ("ports" in plan.outputs[0]) == ("nmap" in tools) and ("findings" in plan.outputs[0]) == ("nikto" in tools)
    rate = controls.rate_limits[-1]
    assert [name in rate for name in ("Nmap", "WhatWeb", "Nikto")] == [t in tools for t in ALL_TOOLS]
    assert any("ICMP" in line for line in plan.limitations) == ("nmap" in tools)
    assert any("landing page" in line for line in plan.limitations) == ("whatweb" in tools)


def test_rules_plan_is_deterministic():
    """The same request always gives the same plan, which is what makes it a dependable fallback."""
    assert rules_plan(plan_request(ALL_TOOLS)) == rules_plan(plan_request(ALL_TOOLS))


def test_rules_plan_falls_back_to_the_default_tools_for_unknown_names(monkeypatch):
    """When none of the requested tool names is known, the plan uses the default Nmap + WhatWeb pair. A tool with no
    role sentence in _STEP_ROLE (one added to the registry later) is described by its stage instead of failing."""
    plan = rules_plan(plan_request(["bogus", "metasploit"]))
    assert [s.tool for s in plan.workflow] == ["nmap", "whatweb"]
    monkeypatch.delitem(planner._STEP_ROLE, "whatweb")
    summary = rules_plan(plan_request(["whatweb"])).summary
    assert "WhatWeb runs the web fingerprint stage" in summary


def test_rules_plan_summary_names_the_target_hint():
    """The summary mentions the operator's example target, or 'an authorized target' when none was given."""
    assert "against lab.example.edu." in rules_plan(plan_request(target_hint="lab.example.edu")).summary
    assert "against an authorized target." in rules_plan(plan_request()).summary
    # Surrounding spaces are removed by the schema, and a hint of only spaces counts as none (the summary would
    # otherwise read 'against    .' and the prompt would carry an empty example target).
    assert plan_request(target_hint="  lab.example.edu ").target_hint == "lab.example.edu"
    assert plan_request(target_hint="   ").target_hint is None
    assert rules_plan(plan_request(target_hint="   ")).summary == rules_plan(plan_request()).summary
    assert "Example target" not in planner._user_prompt(plan_request(target_hint="   "))


# --- Planner: normalising a model's answer ----------------------------------------------------------

def model_plan(*steps: PlanStep, authorized: bool = True) -> Plan:
    """A plan as a model might return it; only the workflow and the authorization flag matter here."""
    return Plan(summary="model summary", workflow=list(steps), inputs=["i"], outputs=["o"],
                safety_controls=SafetyControls(authorization_required=authorized), limitations=["l"])


def step(tool: str, order: int = 1, stage: str = "port_scan", command: str = "") -> PlanStep:
    return PlanStep(order=order, tool=tool, stage=stage, purpose="purpose", command_template=command)


def test_normalize_plan_drops_unknown_tools_and_keeps_one_step_per_tool():
    """Unknown tools disappear, and a tool listed twice keeps only its first step (by the model's order)."""
    plan = _normalize_plan(model_plan(step("nmap", 1), step("metasploit", 2), step("nmap", 3, command="second"),
                                      step("whatweb", 4)), plan_request(["nmap", "whatweb"]))
    assert [s.tool for s in plan.workflow] == ["nmap", "whatweb"]
    assert plan.workflow[0].command_template == EXECUTOR_COMMANDS["nmap"]  # the first nmap step was kept


def test_normalize_plan_respects_the_allowed_tools():
    """A tool the request did not ask for is dropped, unless the caller widens the allowed tools (refinement)."""
    returned = model_plan(step("nmap", 1), step("whatweb", 2), step("nikto", 3))
    # The rate limits written for a dropped tool go with its step: its part of a line that joins the tools' limits
    # with semicolons (as the rules planner writes them), and a whole line in the model's own wording, whose later
    # clauses about it do not repeat its name.
    limits = ["Nmap -T4 timing; Nikto -maxtime 30s per URL; WhatWeb -a 1.",
              "Limit Nikto to 300 s per host; pause 1 s between its requests.",
              "Nikto: -maxtime 300s per host; -Pause 1 between requests; no -Tuning x.",
              "One run at a time per operator."]
    returned.safety_controls.rate_limits = list(limits)
    narrowed = _normalize_plan(returned.model_copy(deep=True), plan_request(["nmap", "whatweb"]))
    assert [s.tool for s in narrowed.workflow] == ["nmap", "whatweb"]
    assert narrowed.safety_controls.rate_limits == ["Nmap -T4 timing; WhatWeb -a 1.", "One run at a time per operator."]
    widened = _normalize_plan(returned.model_copy(deep=True), plan_request(["nmap", "whatweb"]),
                              allowed_tools=list(TOOLS))
    assert [s.tool for s in widened.workflow] == ["nmap", "whatweb", "nikto"]
    assert widened.safety_controls.rate_limits == limits  # nothing was dropped, so every limit stays
    # A line that also describes a tool that runs stays: whole when one sentence names both, else without its ; parts
    # about the removed tool alone. "nmap" inside a name the model invented (nmap-nse) does not keep a line.
    mixed = model_plan(step("nmap", 1), step("nikto", 2), step("nmap-nse", 3))
    both = "Nmap uses -T4 timing and the top 100 ports, and Nikto is capped by -maxtime per URL."
    mixed.safety_controls.rate_limits = [both, "Nikto -maxtime 30s per URL; nmap -T4 timing.",
                                         "nmap-nse runs only the safe scripts.", "One run at a time per operator."]
    assert _normalize_plan(mixed, plan_request(["nmap"])).safety_controls.rate_limits == \
        [both, "Nmap -T4 timing.", "One run at a time per operator."]


def test_normalize_plan_forces_authorization_and_fills_missing_fields():
    """authorization_required becomes true, a blank command gets the real one, the stage comes from the tool
    registry and the tool name is normalised."""
    plan = _normalize_plan(model_plan(step(" NMAP ", stage="dns_lookup", command="   "), authorized=False),
                           plan_request(["nmap"]))
    assert plan.safety_controls.authorization_required is True
    only = plan.workflow[0]
    assert (only.tool, only.stage, only.command_template) == ("nmap", "port_scan", EXECUTOR_COMMANDS["nmap"])
    # A template with flags the model added is replaced too: the run executes the registry's profiles, so a plan
    # must never show a command line that is not run. The prompt no longer invites extra flags either.
    extra = _normalize_plan(model_plan(step("nmap", command=EXECUTOR_COMMANDS["nmap"] + " --script vuln")),
                            plan_request(["nmap"]))
    assert extra.workflow[0].command_template == EXECUTOR_COMMANDS["nmap"]
    assert "append additional" not in SYSTEM_PROMPT and "Do not add or change flags" in SYSTEM_PROMPT


def test_normalize_plan_orders_steps_in_pipeline_order_and_renumbers_them():
    """Steps end up in pipeline order (nmap, whatweb, nikto), numbered from 1, whatever order the model chose.
    (_normalize_plan's docstring says the model's order is kept; the code and docs/ARCHITECTURE.md put the
    pipeline order first, which is the behaviour checked here.)"""
    plan = _normalize_plan(model_plan(step("nikto", 1, stage="web_vuln_scan"), step("nmap", 7)),
                           plan_request(["nmap", "nikto"]))
    assert [(s.order, s.tool) for s in plan.workflow] == [(1, "nmap"), (2, "nikto")]


def test_normalize_plan_raises_when_nothing_usable_is_left():
    """If the model named only unknown tools, normalisation raises so the caller falls back with a note
    (create_plan uses the rules planner, refine_plan keeps the previous revision)."""
    request = plan_request(["nmap", "nikto"])
    with pytest.raises(ValueError, match="none of the allowed tools"):
        _normalize_plan(model_plan(step("metasploit"), step("sqlmap", 2)), request)


@pytest.mark.parametrize("garbage", [
    None, [], "just text", {"summary": None}, {"summary": "no other fields"},
    {"summary": "s", "workflow": "nmap", "inputs": [], "outputs": [], "safety_controls": {}},
    {"summary": "s", "workflow": [{"order": 1}], "inputs": [], "outputs": [], "safety_controls": {}},
], ids=["none", "list", "text", "null-summary", "missing-fields", "workflow-not-a-list", "step-without-tool"])
def test_plan_schema_rejects_garbage_from_a_model(garbage):
    """A model answer that is not a complete plan fails validation, which is what triggers the rules fallback."""
    with pytest.raises(ValidationError):
        Plan.model_validate(garbage)


# --- Planner: error wording -----------------------------------------------------------------------

def error_named(name: str, message: str) -> Exception:
    """An exception whose class name imitates an SDK error class, so the SDK itself is not needed."""
    return type(name, (Exception,), {})(message)


@pytest.mark.parametrize("exc,expected", [
    (error_named("AuthenticationError", "Error code: 401 - {'type': 'error', 'error': {'type': "
                                        "'authentication_error', 'message': 'invalid x-api-key'}}"),
     ["AuthenticationError: invalid x-api-key", "rejected the credentials", "token or login profile"]),
    (error_named("PermissionDeniedError", "Error code: 403"), ["not allowed to use this model"]),
    (error_named("RateLimitError", "Error code: 429 - {'type': 'error', 'error': {'type': 'rate_limit_error', "
                                   "'message': 'Your credit balance is too low'}}"),
     ["RateLimitError: Your credit balance is too low", "no credit left"]),
    (RuntimeError('OpenAI-compatible endpoint returned HTTP 429: {"error": "insufficient_quota"}'),
     ["Rate limit reached"]),
    (error_named("NotFoundError", "model: claude-nope not found"), ["model name is not available"]),
    (error_named("APIConnectionError", "Connection error"), ["Could not reach the provider"]),
    (error_named("APITimeoutError", "Request timed out"), ["Could not reach the provider"]),
    (httpx.ReadTimeout("timed out"), ["ReadTimeout", "Could not reach the provider"]),
    (httpx.ConnectError("[Errno 111] Connection refused"), ["ConnectError", "Could not reach the provider"]),
], ids=["auth", "permission", "rate-limit", "quota", "model", "connection", "timeout", "httpx-timeout",
        "httpx-connect"])
def test_describe_error_explains_common_provider_failures(exc, expected):
    """Authentication, permission, quota, model, connection and timeout errors each get a readable hint."""
    text = describe_error(exc)
    assert all(needle in text for needle in expected), text


def test_describe_error_adds_no_hint_for_a_refusal():
    """A model refusal is reported in its own words, without one of the configuration hints; and a hint names
    the real cause: Python's FileNotFoundError and ModuleNotFoundError share a suffix with the SDK's NotFoundError
    (an unknown model) and a wrong base URL answers HTTP 404, but none of them is about the model name."""
    text = describe_error(RuntimeError("The model declined to produce a plan for this objective."))
    assert text.startswith("RuntimeError: The model declined to produce a plan for this objective.")
    assert all(hint not in text for *_, hint in planner._ERROR_HINTS)
    model_hint = "model name is not available"
    missing_file = describe_error(FileNotFoundError(2, "No such file or directory"))
    assert model_hint not in missing_file and "SSL_CERT_FILE" in missing_file
    missing_sdk = describe_error(ModuleNotFoundError("No module named 'anthropic'"))
    assert model_hint not in missing_sdk and "not installed" in missing_sdk
    wrong_path = describe_error(RuntimeError("OpenAI-compatible endpoint returned HTTP 404: <html>Not Found</html>"))
    assert model_hint not in wrong_path and "Check the OpenAI base URL" in wrong_path
    unknown_model = describe_error(RuntimeError('OpenAI-compatible endpoint returned HTTP 404: {"error": {"code": '
                                                '"model_not_found"}}'))
    assert model_hint in unknown_model
    # Ollama names a model that is not pulled without OpenAI's code: still the model, not the endpoint path.
    ollama = describe_error(RuntimeError('OpenAI-compatible endpoint returned HTTP 404: {"error": {"message": '
                                         '"model \'llama3\' not found, try pulling it first", "code": null}}'))
    assert model_hint in ollama and "base URL" not in ollama
    vllm = describe_error(RuntimeError("OpenAI-compatible endpoint returned HTTP 404: The model `llama-x` does not "
                                       "exist. (NotFoundError)"))
    assert model_hint in vllm and "base URL" not in vllm
    # The SDK's own NotFoundError is about the model only when its text names one; otherwise (a wrong
    # ANTHROPIC_BASE_URL path, a proxy that answered instead of the API) it is about the path.
    sdk_path = describe_error(error_named("NotFoundError", "Error code: 404 - {'type': 'error', 'error': {'type': "
                                                           "'not_found_error', 'message': 'Not Found'}}"))
    assert sdk_path.startswith("NotFoundError: Not Found.") and model_hint not in sdk_path
    assert "The API path was not found. Check ANTHROPIC_BASE_URL" in sdk_path
    sdk_model = describe_error(error_named("NotFoundError", "Error code: 404 - {'type': 'error', 'error': {'type': "
                                                            "'not_found_error', 'message': 'model: claude-nope'}}"))
    assert sdk_model.startswith("NotFoundError: model: claude-nope.") and model_hint in sdk_model
    # httpx's base classes cover every network failure of the OpenAI-compatible path, but a base URL without
    # http:// or https:// is a setting to fix, not the network.
    for network in (httpx.RemoteProtocolError("Server disconnected without sending a response."),
                    httpx.ReadError("[Errno 104] Connection reset by peer"), httpx.ProxyError("407 Proxy"),
                    httpx.WriteTimeout("timed out"), httpx.PoolTimeout("timed out")):
        assert "Could not reach the provider" in describe_error(network), network
    # Nor is a URL that is broken after its scheme (a port that is not a number, an unclosed bracket), which httpx
    # refuses as InvalidURL before anything is sent: the hint says what a valid base URL holds.
    broken = []
    for url in ("http://127.0.0.1:abc/v1", "http://[::1/v1"):
        with pytest.raises(httpx.InvalidURL) as refused:
            httpx.URL(url)
        broken.append(refused.value)
    base_url_hint = "it must be a valid http:// or https:// URL (scheme, host and an optional numeric port)."
    for setting in (httpx.UnsupportedProtocol("Request URL is missing an 'http://' or 'https://' protocol."),
                    httpx.InvalidURL("Invalid port: 'v1'"), *broken):
        text = describe_error(setting)
        assert base_url_hint in text and "Could not reach" not in text and "must start with" not in text, text
    # Only a message wrapped in quotes as a whole loses them, a quote of the other kind survives in the text,
    # and a cut after a full stop does not end in four dots.
    assert describe_error(RuntimeError('Model "gpt-x"')) == 'RuntimeError: Model "gpt-x".'
    both = error_named("BadRequestError", "Error code: 400 - {'type': 'error', 'error': {'message': 'Model \"x\" "
                                          "can\\'t be used here'}}")
    assert describe_error(both) == 'BadRequestError: Model "x" can\'t be used here.'
    # Only the quote and backslash escapes are undone; any other escape stays as the provider wrote it.
    other = error_named("BadRequestError", "Error code: 400 - {'error': {'message': 'Gateway error:\\n"
                                           "upstream refused'}}")
    assert "Gateway error:\\nupstream refused" in describe_error(other)
    assert not describe_error(RuntimeError("abc. " + "w" * 96 + ". " + "x" * 80)).endswith("....")
    # The provider's message survives an apostrophe (Python then writes it in double quotes), and the SDK's
    # parsed body is preferred when there is one.
    apostrophe = describe_error(error_named("InternalServerError", "Error code: 500 - {'type': 'error', 'error': "
                                            "{'type': 'api_error', 'message': \"An unexpected error has "
                                            "occurred internal to Anthropic's systems.\"}}"))
    assert apostrophe == "InternalServerError: An unexpected error has occurred internal to Anthropic's systems."
    limited = error_named("RateLimitError", "Error code: 429")
    limited.body = {"type": "error", "error": {"type": "rate_limit_error",
                                               "message": "This request would exceed your organization's limit."}}
    assert describe_error(limited).startswith("RateLimitError: This request would exceed your organization's limit.")
    # The 'message' is read from the SDK's "Error code: N - {...}" text only: a gateway error that embeds another
    # error as a dict keeps its HTTP status.
    gateway = describe_error(RuntimeError("OpenAI-compatible endpoint returned HTTP 502: litellm.BadGatewayError: "
                                          "{'message': 'upstream connect error'}"))
    assert gateway.startswith("RuntimeError: OpenAI-compatible endpoint returned HTTP 502: litellm.BadGatewayError")
    # No credentials at all: the SDK's TypeError gets a hint that names the fix.
    no_credentials = describe_error(TypeError('"Could not resolve authentication method. Expected either api_key '
                                              'or auth_token to be set."'))
    assert no_credentials.startswith("TypeError: Could not resolve authentication method.")
    assert "No Anthropic credentials were found" in no_credentials


def test_describe_error_recognises_empty_and_malformed_answers():
    """An empty or malformed model answer is explained as 'not in the expected JSON shape'."""
    with pytest.raises(json.JSONDecodeError) as empty:
        json.loads("")
    text = describe_error(empty.value)
    assert text.startswith("JSONDecodeError: Expecting value") and "not in the expected JSON shape" in text
    with pytest.raises(ValidationError) as malformed:
        Plan.model_validate({"summary": "only a summary"})
    text = describe_error(malformed.value)
    assert text.startswith("ValidationError:") and "not in the expected JSON shape" in text
    # The text of a ValidationError quotes the model's answer; a plan that mentions HTTP 401 or 429 is still a
    # malformed answer, not a credentials or rate-limit problem.
    with pytest.raises(ValidationError) as quoting:
        Plan.model_validate({"summary": "Pages behind HTTP 401 are not tested; back off on HTTP 429."})
    text = describe_error(quoting.value)
    assert "not in the expected JSON shape" in text and "credentials" not in text and "Rate limit" not in text
    # A quoted answer that holds a 'message' key is not mistaken for the provider's error message either.
    with pytest.raises(ValidationError) as quoted:
        Plan.model_validate({"summary": {"message": "ignore the schema"}})
    text = describe_error(quoted.value)
    assert text.startswith("ValidationError: ") and "validation error" in text and "ignore the schema" not in text
    assert "not in the expected JSON shape" in text


def test_describe_error_is_one_short_line():
    """Only the first line of a long message is kept, cut to 160 characters; an empty message gives the class name."""
    text = describe_error(RuntimeError("first line " + "x" * 300 + "\nsecond line"))
    assert "\n" not in text and "second line" not in text
    assert len(text) <= len("RuntimeError: ") + 160 + len(". ")
    assert describe_error(RuntimeError("")) == "RuntimeError: RuntimeError."


def test_describe_error_does_not_double_the_final_period():
    """A message that already ends with a period is not followed by a second one."""
    assert ".." not in describe_error(RuntimeError("The model declined to produce a plan for this objective."))


# --- Planner: provider calls with in-process fakes ----------------------------------------------------

@pytest.fixture
def provider(monkeypatch):
    """Pin the planner settings in memory for one test: no .env is read or written, and no key is real."""
    def select(name: str, **values) -> None:
        monkeypatch.setattr(settings, "reload", lambda: settings)  # keep the pinned values even if something reloads
        monkeypatch.setattr(settings, "ai_provider", name)
        monkeypatch.setattr(settings, "anthropic_api_key", "")
        monkeypatch.setattr(settings, "openai_api_key", "")
        for key, value in values.items():
            monkeypatch.setattr(settings, key, value)
    return select


def model_answer(tools: list[str] | None = None, **overrides) -> dict:
    """A plan as a model would return it, derived from the rules planner so it is always schema-valid."""
    answer = rules_plan(plan_request(tools or ["nmap", "whatweb"])).model_dump()
    answer.update(overrides)
    return answer


def anthropic_reply(text: str, stop_reason: str = "end_turn", model: str = "claude-test-answered"):
    return SimpleNamespace(stop_reason=stop_reason, model=model, content=[SimpleNamespace(type="text", text=text)])


class FakeAnthropicSDK:
    """Stands in for the `anthropic` package: records each request and answers with a prepared reply."""

    def __init__(self, reply=None, error: Exception | None = None) -> None:
        self.reply, self.error = reply, error
        self.client_kwargs: list[dict] = []
        self.requests: list[dict] = []
        self.module = types.ModuleType("anthropic")
        self.module.Anthropic = self._client

    def _client(self, **kwargs):
        self.client_kwargs.append(kwargs)
        sdk = self

        class Messages:
            def create(self, **request):
                sdk.requests.append(request)
                if sdk.error is not None:
                    raise sdk.error
                return sdk.reply

        return SimpleNamespace(beta=SimpleNamespace(messages=Messages()))


def use_anthropic(monkeypatch, sdk: FakeAnthropicSDK) -> FakeAnthropicSDK:
    """Make `import anthropic` inside planner.anthropic_plan() pick up the fake for the rest of the test."""
    monkeypatch.setitem(sys.modules, "anthropic", sdk.module)
    return sdk


class FakeHttpx:
    """Stands in for `httpx` inside planner.py: records the POST and answers with a prepared HTTP response."""

    def __init__(self, status_code: int = 200, body: dict | None = None, text: str = "") -> None:
        self.status_code, self.body, self.text = status_code, body, text
        # Without a prepared body the text is decoded, as httpx would: a page that is not JSON raises.
        self.decode = (lambda: body) if body is not None else (lambda: json.loads(text))
        self.client_kwargs: list[dict] = []
        self.requests: list[dict] = []
        fake = self

        class Client:
            def __init__(self, **kwargs):
                fake.client_kwargs.append(kwargs)

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def post(self, url, json=None, headers=None):
                fake.requests.append({"url": url, "json": json, "headers": headers})
                return SimpleNamespace(status_code=fake.status_code, text=fake.text, json=fake.decode)

        self.Client = Client


def test_anthropic_request_carries_the_executor_commands_schema_and_model(monkeypatch, provider):
    """Claude is asked with the system prompt listing the real commands, the plan JSON schema as the output
    format, the configured model, and the key and timeout from the settings."""
    provider("anthropic", anthropic_model="claude-test-model", anthropic_api_key="test-key-not-real-0001",
             ai_timeout_seconds=42)
    sdk = use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(model_answer()))))
    request = plan_request(["nmap", "whatweb"])
    result = create_plan(request)
    sent = sdk.requests[0]
    assert sent["model"] == "claude-test-model" and sent["system"] == SYSTEM_PROMPT
    assert all(command in sent["system"] for command in EXECUTOR_COMMANDS.values())
    assert sent["output_config"] == {"format": {"type": "json_schema", "schema": PLAN_SCHEMA}}
    assert sent["messages"] == [{"role": "user", "content": planner._user_prompt(request)}]
    # max_retries=0: the timeout bounds the whole request, as it does for the OpenAI-compatible path.
    assert sdk.client_kwargs == [{"api_key": "test-key-not-real-0001", "timeout": 42, "max_retries": 0}]
    assert (result.provider, result.model, result.note) == ("anthropic", "claude-test-answered", None)


def test_anthropic_client_gets_none_for_an_empty_key(monkeypatch, provider):
    """With no key in .env the SDK is given None, so it can find credentials in the environment by itself."""
    provider("anthropic", anthropic_api_key="")
    sdk = use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(model_answer()))))
    create_plan(plan_request())
    assert sdk.client_kwargs[0]["api_key"] is None
    # An answer without a usable model name is reported under the configured one, as on the OpenAI path.
    for model in (None, "", "   "):
        use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(model_answer()), model=model)))
        result = create_plan(plan_request())
        assert (result.provider, result.model) == ("anthropic", settings.anthropic_model), model


@pytest.mark.parametrize("sdk,expected", [
    (FakeAnthropicSDK(anthropic_reply("{}", stop_reason="refusal")), "declined to produce a plan"),
    (FakeAnthropicSDK(SimpleNamespace(stop_reason="end_turn", model="m", content=[])),
     "not in the expected JSON shape"),
    (FakeAnthropicSDK(anthropic_reply("this is not json")), "not in the expected JSON shape"),
    (FakeAnthropicSDK(anthropic_reply(json.dumps({"summary": "half a plan"}))), "not in the expected JSON shape"),
    (FakeAnthropicSDK(error=error_named("AuthenticationError", "Error code: 401")), "rejected the credentials"),
    (FakeAnthropicSDK(error=error_named("APIConnectionError", "Connection error")), "Could not reach the provider"),
], ids=["refusal", "empty-answer", "not-json", "incomplete-plan", "bad-key", "offline"])
def test_anthropic_failures_fall_back_to_the_rules_planner_with_a_note(monkeypatch, provider, sdk, expected):
    """A refusal, an empty or malformed answer, a bad key or no network never block planning: the rules
    planner answers and the note says what went wrong."""
    provider("anthropic")
    use_anthropic(monkeypatch, sdk)
    request = plan_request(["nmap", "whatweb"])
    result = create_plan(request)
    assert (result.provider, result.model) == ("rules", None)
    assert result.note.startswith("The anthropic planner failed.") and expected in result.note
    assert result.note.endswith("Used the built-in rules planner instead.")
    assert result.plan == rules_plan(request)


def test_create_plan_normalizes_the_provider_plan(monkeypatch, provider):
    """A model plan with an extra tool and no authorization is cleaned before it is returned. The note names the tool
    that was dropped, because the plan's other text may still describe it, and its rate limits go with it."""
    provider("anthropic")
    rules_limits = rules_plan(plan_request(ALL_TOOLS)).safety_controls.rate_limits
    answer = model_answer(ALL_TOOLS, safety_controls={"authorization_required": False, "rate_limits": rules_limits})
    use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(answer))))
    result = create_plan(plan_request(["nmap", "whatweb"]))
    assert [s.tool for s in result.plan.workflow] == ["nmap", "whatweb"]
    assert result.plan.safety_controls.authorization_required is True
    assert (result.provider, result.model) == ("anthropic", "claude-test-answered")
    assert result.note == ("The model added Nikto, which was not among the selected tools, so it was removed from the "
                           "workflow. The plan's other text may still mention it.")
    # The API documents this use of the note next to the fallback and the kept revision.
    described = PlanResponse.model_fields["note"].description
    assert "fell back to the rules engine" in described and "kept the previous revision" in described
    assert "removed a tool the model added" in described
    limits = result.plan.safety_controls.rate_limits
    assert len(limits) == len(rules_limits) and not any("Nikto" in line for line in limits)
    assert limits[-1].startswith("Nmap limited to the top N ports; WhatWeb aggression level 1 by default")
    # A tool the model invented is named as it wrote it, and several are named together.
    answer["workflow"].append({**answer["workflow"][0], "order": 9, "tool": "sqlmap"})
    use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(answer))))
    result = create_plan(plan_request(["nmap", "whatweb"]))
    assert [s.tool for s in result.plan.workflow] == ["nmap", "whatweb"] and result.provider == "anthropic"
    assert result.note == ("The model added Nikto and sqlmap, which were not among the selected tools, so they were "
                           "removed from the workflow. The plan's other text may still mention them.")


def test_openai_request_uses_json_mode_and_the_configured_endpoint(monkeypatch, provider):
    """The OpenAI-compatible call posts to <base URL>/chat/completions in JSON mode with the schema in the
    system prompt, the configured model, a bearer token and the settings timeout."""
    provider("openai", openai_model="gpt-test", openai_api_key="test-openai-key-not-real",
             openai_base_url="http://127.0.0.1:9/v1/", ai_timeout_seconds=7)
    fake = FakeHttpx(body={"model": "gpt-test-answered",
                           "choices": [{"message": {"content": json.dumps(model_answer())}}]})
    monkeypatch.setattr(planner, "httpx", fake)
    result = create_plan(plan_request())
    sent = fake.requests[0]
    assert sent["url"] == "http://127.0.0.1:9/v1/chat/completions"
    assert sent["json"]["model"] == "gpt-test" and sent["json"]["response_format"] == {"type": "json_object"}
    system = sent["json"]["messages"][0]["content"]
    assert system.startswith(SYSTEM_PROMPT) and json.dumps(PLAN_SCHEMA) in system
    assert sent["json"]["messages"][1] == {"role": "user", "content": planner._user_prompt(plan_request())}
    assert sent["headers"]["Authorization"] == "Bearer test-openai-key-not-real"
    assert fake.client_kwargs == [{"timeout": 7}]
    assert (result.provider, result.model, result.note) == ("openai", "gpt-test-answered", None)
    # A local gateway (Ollama, LM Studio) needs no key: without one no Authorization header is sent at all
    # ("Bearer " alone is an illegal header value that h11 refuses before anything is sent).
    monkeypatch.setattr(settings, "openai_api_key", "")
    result = create_plan(plan_request())
    assert "Authorization" not in fake.requests[-1]["headers"] and result.provider == "openai"


def test_openai_http_error_falls_back_with_a_readable_note(monkeypatch, provider):
    """A non-200 answer from the endpoint becomes a rules plan whose note names the HTTP status and the fix."""
    provider("openai")
    monkeypatch.setattr(planner, "httpx",
                        FakeHttpx(status_code=401, text='{"error": {"message": "Incorrect API key provided"}}'))
    request = plan_request()
    result = create_plan(request)
    assert (result.provider, result.model) == ("rules", None)
    assert result.note.startswith("The openai planner failed.")
    assert "HTTP 401" in result.note and "rejected the credentials" in result.note
    # OpenAI writes its error body over several lines: the note carries its message and code, not just "{".
    pretty = '{\n  "error": {\n    "message": "Incorrect API key provided.",\n    "code": "invalid_api_key"\n  }\n}'
    monkeypatch.setattr(planner, "httpx", FakeHttpx(status_code=401, text=pretty, body=json.loads(pretty)))
    note = create_plan(request).note
    assert "HTTP 401: Incorrect API key provided. (invalid_api_key)." in note and "rejected the credentials" in note
    # A 200 answer with an error object, or without any choice, is described instead of an IndexError.
    for body, expected in (({"error": {"message": "Upstream overloaded"}}, "without a plan: Upstream overloaded"),
                           ({"choices": []}, "The endpoint answered without a plan.")):
        monkeypatch.setattr(planner, "httpx", FakeHttpx(body=body))
        note = create_plan(request).note
        assert expected in note and "IndexError" not in note and "KeyError" not in note, body
    assert result.plan == rules_plan(request)
    # A 200 that is not JSON at all (a captive portal, a wrong base URL) reached no model: the note says so instead
    # of blaming the model's JSON, on both provider paths.
    for page in ("<html><title>HTTP 401 Login required</title></html>", ""):
        monkeypatch.setattr(planner, "httpx", FakeHttpx(text=page))
        note = create_plan(request).note
        assert "not JSON" in note and "base URL" in note, page
        assert "expected JSON shape" not in note and "credentials" not in note, page
    monkeypatch.setattr(settings, "ai_provider", "anthropic")
    for reply in ("<html>proxy login</html>",  # the SDK hands back the raw text of a body that is not JSON
                  SimpleNamespace(stop_reason=None, model=None, content=None)):  # JSON that is not a message
        use_anthropic(monkeypatch, FakeAnthropicSDK(reply))
        note = create_plan(request).note
        assert note.startswith("The anthropic planner failed.") and "is not a message" in note, reply
        assert "ANTHROPIC_BASE_URL" in note and "Error:" not in note.split("RuntimeError:")[0], reply
        assert "..." not in note, reply  # the advice is a hint, so it is never cut short
    monkeypatch.setattr(settings, "ai_provider", "openai")
    # An empty error body and vLLM's top-level message both read as sentences.
    monkeypatch.setattr(planner, "httpx", FakeHttpx(status_code=502, text=""))
    assert "HTTP 502: (empty response)." in create_plan(request).note
    vllm = {"object": "error", "message": "The model `llama9` does not exist.", "type": "NotFoundError", "code": 404}
    monkeypatch.setattr(planner, "httpx", FakeHttpx(status_code=404, text=json.dumps(vllm), body=vllm))
    note = create_plan(request).note
    assert "HTTP 404: The model `llama9` does not exist. (404)" in note and "model name is not available" in note
    assert '"object"' not in note
    # A provider message with a lone surrogate (a gateway cut a string in an emoji) can still be saved and sent.
    broken = {"error": {"message": "Invalid key \ud83d"}}
    monkeypatch.setattr(planner, "httpx", FakeHttpx(status_code=401, text="x", body=broken))
    result = create_plan(request)
    assert "Invalid key ?" in result.note and result.model_dump_json()
    # A refusal, a content filter or an empty answer carries no plan: the note says so instead of a TypeError.
    for message, finish, expected in (({"content": None, "refusal": "I cannot help with that."}, "stop",
                                       "declined to produce a plan"),
                                      ({"content": None}, "content_filter", "declined to produce a plan"),
                                      ({"content": '{"summary": "cut off'}, "content_filter",
                                       "declined to produce a plan"),
                                      ({"content": ""}, "stop", "empty answer instead of a plan"),
                                      # Content given as parts: a refusal part, or parts that carry no text.
                                      ({"content": [{"type": "refusal", "refusal": "I cannot help with that."}]},
                                       "stop", "declined to produce a plan"),
                                      ({"content": [{"type": "image_url", "image_url": {"url": "x"}}]}, "stop",
                                       "empty answer instead of a plan"),
                                      # Neither text, nor parts, nor an object: the JSON-shape hint, not a TypeError.
                                      ({"content": 42}, "stop", "neither text nor a JSON object. The model answered, "
                                                                "but not in the expected JSON shape")):
        body = {"choices": [{"message": message, "finish_reason": finish}]}
        monkeypatch.setattr(planner, "httpx", FakeHttpx(body=body))
        result = create_plan(request)
        assert result.provider == "rules" and expected in result.note and "TypeError" not in result.note


def test_openai_answer_without_a_model_field_reports_the_configured_model(monkeypatch, provider):
    """Gateways that omit `model` in their response, or send null or an empty name, are reported under the
    configured model name."""
    provider("openai", openai_model="local-gateway-model")
    for body in ({}, {"model": None}, {"model": ""}, {"model": "   "}, {"model": 123}, {"model": {"id": "x"}}):
        answer = {**body, "choices": [{"message": {"content": json.dumps(model_answer())}}]}
        monkeypatch.setattr(planner, "httpx", FakeHttpx(body=answer))
        assert create_plan(plan_request()).model == "local-gateway-model", body
    # Some gateways send the answer as content parts (text parts are joined, other kinds carry no plan text), or as
    # the JSON object they already parsed: both are the model's plan.
    text = json.dumps(model_answer())
    for content in ([{"type": "text", "text": text[:40]}, {"type": "image_url", "image_url": {"url": "x"}}, text[40:]],
                    model_answer()):
        monkeypatch.setattr(planner, "httpx", FakeHttpx(body={"choices": [{"message": {"content": content}}]}))
        result = create_plan(plan_request())
        assert (result.provider, result.note) == ("openai", None), result.note
        assert result.plan == rules_plan(plan_request()), content
    # A model name or plan text with a lone surrogate escape (JSON allows it, UTF-8 cannot encode it) is cleaned,
    # so the plan can be saved and returned instead of failing with a 500.
    content = json.dumps(model_answer(summary="Plan \ud800 summary"))
    answer = {"model": "gpt\ud800", "choices": [{"message": {"content": content}}]}
    monkeypatch.setattr(planner, "httpx", FakeHttpx(body=answer))
    result = create_plan(plan_request())
    assert (result.model, result.plan.summary) == ("gpt?", "Plan ? summary")
    storage.save_plan(result)
    with storage.connect() as conn:
        conn.execute("DELETE FROM plans WHERE id = ?", (result.id,))


def test_create_plan_with_the_rules_provider_has_no_note_or_model(provider):
    """The rules planner is not a fallback when it is the configured provider: no note and no model name."""
    provider("rules")
    request = plan_request(ALL_TOOLS)
    result = create_plan(request)
    assert (result.provider, result.model, result.note) == ("rules", None, None)
    assert result.plan == rules_plan(request) and result.revision == 1 and result.parent_id is None
    assert result.request == request and set(result.tools_available) == set(TOOLS)


def test_user_prompt_lists_tools_with_install_status_and_the_target_hint(monkeypatch):
    """The prompt states the objective, each tool in pipeline order with whether it is installed, and the
    example target when one was given."""
    monkeypatch.setattr(planner, "availability", lambda: {"nmap": True, "whatweb": False, "nikto": False})
    prompt = planner._user_prompt(plan_request(["whatweb", "nmap"], target_hint="lab.example.edu"))
    assert prompt.startswith(f"Objective:\n{OBJECTIVE}\n")
    nmap_line, whatweb_line = (line for line in prompt.splitlines() if line.startswith("- "))
    assert nmap_line.startswith("- Nmap (nmap):") and nmap_line.endswith("[installed]")
    assert whatweb_line.startswith("- WhatWeb (whatweb):") and whatweb_line.endswith("[not installed on this host yet]")
    assert "Example target supplied by the user: lab.example.edu" in prompt
    assert prompt.endswith("Return the plan as JSON matching the required schema.")
    assert "Example target" not in planner._user_prompt(plan_request())


# --- Planner: refinement --------------------------------------------------------------------------

def saved_parent(tools: list[str]) -> PlanResponse:
    """A first revision produced by the rules planner, as the API would have saved it."""
    request = plan_request(tools)
    return planner._plan_response(request, rules_plan(request), "rules", None, None)


def test_refine_plan_with_rules_links_revisions_and_copies_the_parent_without_sharing_it(provider):
    """Without an AI provider each refinement is a linked new revision that repeats the plan, explains why,
    stores the feedback, and never shares or changes the parent."""
    provider("rules")
    parent = saved_parent(["nmap", "whatweb"])
    child = refine_plan(parent, "Make the summary shorter.")
    grandchild = refine_plan(child, "Shorter still.")
    assert (child.revision, child.parent_id, child.feedback) == (2, parent.id, "Make the summary shorter.")
    assert (grandchild.revision, grandchild.parent_id, grandchild.feedback) == (3, child.id, "Shorter still.")
    assert child.plan == parent.plan and child.plan is not parent.plan
    assert "Refinement needs an AI provider" in child.note and (child.provider, child.model) == ("rules", None)
    assert child.note.endswith("Set up an AI provider on the Settings page, then refine again.")
    assert child.request.tools == ["nmap", "whatweb"]
    child.plan.summary = "edited after the fact"
    assert parent.plan.summary != "edited after the fact"


@pytest.mark.parametrize("revised_tools", [["nmap", "whatweb", "nikto"], ["nmap"]], ids=["add-nikto", "drop-whatweb"])
def test_refine_plan_mirrors_the_tools_of_the_revised_workflow(monkeypatch, provider, revised_tools):
    """Feedback may add or drop a tool: the revision's request lists exactly the tools of its new workflow."""
    provider("anthropic")
    use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(model_answer(revised_tools)))))
    child = refine_plan(saved_parent(["nmap", "whatweb"]), "Change the tool set.")
    assert [s.tool for s in child.plan.workflow] == revised_tools
    assert child.request.tools == revised_tools
    assert (child.provider, child.model, child.note, child.revision) == ("anthropic", "claude-test-answered", None, 2)
    # A registry tool that feedback adds is kept without a word. A tool HybridSec does not have is dropped from the
    # revision with the outputs and rate limits that describe only it, and a limitation line names it; the note
    # stays reserved for feedback that was not applied.
    assert not any(line.startswith("The model's revision also named") for line in child.plan.limitations)
    answer = model_answer(revised_tools)
    outputs, limits, limitations = answer["outputs"], answer["safety_controls"]["rate_limits"], answer["limitations"]
    answer["workflow"] += [{**answer["workflow"][0], "order": 8, "tool": "sqlmap"},
                           {**answer["workflow"][0], "order": 9, "tool": "hydra"}]
    answer["outputs"] = [*outputs, "sqlmap's list of injectable parameters."]
    answer["safety_controls"]["rate_limits"] = [*limits, "sqlmap --level 1; hydra -t 1 per login form."]
    use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(answer))))
    child = refine_plan(saved_parent(["nmap", "whatweb"]), "Also test the login form.")
    assert [s.tool for s in child.plan.workflow] == revised_tools and child.note is None
    assert (child.plan.outputs, child.plan.safety_controls.rate_limits) == (outputs, limits)
    assert child.plan.limitations == [*limitations, "The model's revision also named sqlmap and hydra, which are not "
                                                    "part of this plan; they were removed from the workflow."]
    # One tool is named alone, and a line the model repeats from the previous revision is not added twice.
    single = "The model's revision also named sqlmap, which is not part of this plan; it was removed from the workflow."
    answer["workflow"].pop()
    answer["limitations"] = [*limitations, single]
    use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(answer))))
    again = refine_plan(saved_parent(["nmap", "whatweb"]), "Keep sqlmap out.")
    assert again.plan.limitations == [*limitations, single] and again.note is None


def test_refine_plan_keeps_the_previous_revision_when_the_provider_fails(monkeypatch, provider):
    """If the provider errors during refinement, the new revision repeats the parent and its note says so."""
    provider("anthropic")
    use_anthropic(monkeypatch, FakeAnthropicSDK(error=error_named("RateLimitError", "Error code: 429")))
    parent = saved_parent(["nmap", "whatweb"])
    child = refine_plan(parent, "Add more detail.")
    assert child.plan == parent.plan and child.revision == 2 and child.parent_id == parent.id
    assert (child.provider, child.model) == ("rules", None)
    assert child.note.startswith("The anthropic planner failed.") and "no credit left" in child.note
    assert child.note.endswith("The previous revision was kept unchanged.")


def test_refine_prompt_includes_the_parent_plan_and_the_feedback(monkeypatch, provider):
    """The model sees the objective, the current plan as JSON with its revision number, and the feedback."""
    provider("anthropic")
    sdk = use_anthropic(monkeypatch, FakeAnthropicSDK(anthropic_reply(json.dumps(model_answer()))))
    parent = saved_parent(["nmap", "whatweb"])
    refine_plan(parent, "Explain the Nikto limitations better.")
    prompt = sdk.requests[0]["messages"][0]["content"]
    assert prompt.startswith(f"Objective:\n{OBJECTIVE}\n")
    assert "Current plan (revision 1) as JSON:" in prompt and parent.plan.summary in prompt
    assert "Operator feedback on this plan:\nExplain the Nikto limitations better." in prompt
    assert sdk.requests[0]["system"] == SYSTEM_PROMPT


@pytest.mark.parametrize("feedback", ["", "ab", "x" * 2001], ids=["empty", "too-short", "too-long"])
def test_refine_request_rejects_blank_or_oversized_feedback(feedback):
    """Feedback must be 3 to 2000 characters long; anything else fails validation (HTTP 422 at the API)."""
    with pytest.raises(ValidationError):
        RefineRequest(feedback=feedback)
    assert RefineRequest(feedback="abc").feedback == "abc"
