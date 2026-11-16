"""Regression tests for the Nmap command review of November 2026: partial results are visible in every view
of a run, host-timeout notes name their hosts, and a host name that resolves only to IPv6 is scanned with -6.

Like the rest of the suite these run offline: scanners are fakes, the resolver is replaced, and importing
tests.test_api first points the app at a private .env file and a temporary data directory.
"""
from __future__ import annotations

import csv
import io
import json
import socket
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import hybrid, storage
from app.compare import compare_runs
from app.config import BASE_DIR
from app.hybrid import RunManager, summarize
from app.main import app
from app.reports import coverage_label, render_csv, render_html, render_markdown
from app.routers.settings_api import require_local
from app.schemas import ExecuteRequest, PortFinding, Run, StageResult, VulnFinding
from app.tools import parsers
from app.tools.runner import CommandResult
from tests.test_api import make_run, run_stage_handler

NMAP_HEAD = '<?xml version="1.0"?><nmaprun scanner="nmap">'
HOST_WITH_PORTS = (
    '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/><ports>'
    '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>'
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>'
    '</ports></host>'
)
# Nmap writes a host that hit --host-timeout without a port table: its ports are missing, not incomplete.
TIMED_OUT_HOST = '<host timedout="true"><status state="up"/><address addr="10.10.20.9" addrtype="ipv4"/></host>'
IPV6_HOST = (
    '<host><status state="up"/><address addr="2001:db8::5" addrtype="ipv6"/><ports>'
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host>'
)
WEB_TARGETS = [PortFinding(host="10.10.20.5", port=80, service="http", is_web=True),
               PortFinding(host="10.10.20.5", port=8080, service="http", is_web=True)]


# --- Fixtures and helpers -------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def database_tables():
    """Runs are saved to SQLite; the app's startup normally creates the tables, so create them here."""
    storage.init_db()


@pytest.fixture(scope="module")
def client():
    """One API client for the module. Its peer is "testclient", so the loopback-only settings guard is overridden."""
    app.dependency_overrides[require_local] = lambda: None
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def fake_nmap(monkeypatch, stdout: str, *, timed_out: bool = False, exit_code: int = 0) -> None:
    """Pretend the scanners are installed, make every call return `stdout`, and answer name lookups with IPv4
    only, so no test ever starts a scanner or asks a real resolver."""
    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", lambda command, timeout: CommandResult(
        command=command, exit_code=None if timed_out else exit_code, stdout=stdout, stderr="",
        duration_seconds=0.1, timed_out=timed_out))
    monkeypatch.setattr(hybrid, "_address_families", lambda hostname: {socket.AF_INET})


def forbid_lookups(monkeypatch) -> None:
    """Fail the test if the pipeline asks the resolver about a target."""
    def forbidden(hostname: str) -> set[int]:
        raise AssertionError(f"the resolver was consulted for {hostname}")
    monkeypatch.setattr(hybrid, "_address_families", forbidden)


def nmap_run(run_id: str, target: str = "10.10.20.0/24", **fields) -> Run:
    """A running live-mode Run with one pending port-scan stage (a 30 s stage budget gives a 24 s host timeout)."""
    values = {"id": run_id, "target": target, "status": "running", "tools": ["nmap"],
              "stages": [StageResult(stage="port_scan", tool="nmap")]}
    values.update(fields)
    return make_run(**values)


def web_run(run_id: str) -> Run:
    """A running live-mode Run whose port scan is done and whose two web stages are still pending."""
    return make_run(id=run_id, target="10.10.20.5", status="running", tools=["nmap", "whatweb", "nikto"],
                    stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                            StageResult(stage="web_fingerprint", tool="whatweb"),
                            StageResult(stage="web_vuln_scan", tool="nikto")])


def execute_and_wait(request: ExecuteRequest, tools: list[str], budget: int = 60) -> Run:
    """Run the whole pipeline on a fresh RunManager and return the stored final state."""
    manager = RunManager()
    run = manager.create(request, request.target, tools, None, budget)
    deadline = time.monotonic() + 10
    while manager.is_active(run.id) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not manager.is_active(run.id), "the run did not finish in time"
    return storage.get_run(run.id)


def report_path(command: list[str]) -> str:
    """The report file a fake WhatWeb or Nikto call must write, taken from the command line."""
    for index, part in enumerate(command):
        if part.startswith("--log-json="):
            return part.split("=", 1)[1]
        if part == "-output":
            return command[index + 1]
    raise AssertionError(f"no report file in {command}")


def write_whatweb_report(command: list[str]) -> None:
    with open(report_path(command), "w", encoding="utf-8") as fh:
        fh.write(json.dumps([{"target": command[-1], "http_status": 200,
                              "plugins": {"HTTPServer": {"string": ["nginx"]}}}]))


# --- A range scan stopped at the stage time limit -------------------------------------------------

def test_range_scan_stopped_at_the_time_limit_is_marked_partial_in_every_view(monkeypatch):
    """Killed at the stage time limit after one complete host, the stage completes with the salvaged ports but
    is marked partial, and so are the run summary, the history entry, the three text reports and the
    comparison. Before the fix only the stage note said so: the history, the CSV and the comparison showed
    the run as complete, and a comparison listed the unscanned ports as closed."""
    cut_off = NMAP_HEAD + HOST_WITH_PORTS + '<host><status state="up"/><address addr="10.10.20.6" addrty'
    fake_nmap(monkeypatch, cut_off, timed_out=True)
    run = execute_and_wait(ExecuteRequest(target="10.10.20.0/24", authorized=True), ["nmap"], budget=60)
    try:
        stage = run.stages[0]
        assert run.status == "completed" and run.error is None
        assert stage.status == "completed" and stage.partial is True
        assert "stopped at the 60s stage time limit" in stage.error and "truncated after 1 host(s)" in stage.error
        assert "results are partial" in stage.error and "Increase the time budget" in stage.error
        assert [p.port for p in run.ports] == [22, 80]
        assert run.summary.partial is True and run.summary.hosts_up == 1 and run.summary.open_ports == 2
        assert any("2 open port(s) (partial)" in line for line in run.log)

        listed = next(item for item in storage.list_runs() if item.id == run.id)
        assert listed.status == "completed" and listed.summary.partial is True

        rows = list(csv.reader(io.StringIO(render_csv(run))))
        assert rows[0][-2:] == ["coverage", "mode"] and len(rows) == 3
        assert all(row[-2:] == ["partial", "live"] for row in rows[1:])
        markdown = render_markdown(run)
        assert "**Status:** completed (partial results)" in markdown
        assert "> **Partial results.** nmap: nmap was stopped at the 60s stage time limit" in markdown
        html = render_html(run)
        assert "completed (partial results)" in html and "<b>Partial results.</b> nmap: nmap was stopped" in html

        baseline = make_run(id="nmrevbase001", target="10.10.20.0/24", status="completed", tools=["nmap"],
                            ports=[*run.ports, PortFinding(host="10.10.20.6", port=443, service="https")],
                            stages=[StageResult(stage="port_scan", tool="nmap", status="completed")])
        baseline.summary = summarize(baseline, 2)
        diff = compare_runs(baseline, run)
        assert [p.port for p in diff.ports_removed] == [443]  # the diff is the same; the note qualifies it
        assert diff.note.startswith("The other run has partial results") and "not evidence" in diff.note
        assert diff.base.summary.partial is False and diff.other.summary.partial is True
        assert compare_runs(run, baseline).note.startswith("The base run has partial results")
        assert compare_runs(run, run).note.startswith("Both runs have partial results")
        assert compare_runs(baseline, baseline).note is None
    finally:
        storage.delete_run(run.id)


def test_output_cut_off_without_a_timeout_is_partial_too(monkeypatch):
    """Nmap crashed or its output hit the cap: the XML is cut off although the process was not killed."""
    fake_nmap(monkeypatch, NMAP_HEAD + HOST_WITH_PORTS + '<host><status state="up"/><addr')
    run = nmap_run("nmrev0000002")
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "completed" and stage.partial is True and len(run.ports) == 2
    assert stage.error == ("nmap output was truncated after 1 host(s), so results are partial. "
                           "Increase the time budget or reduce top_ports.")


def test_a_quiet_target_is_a_complete_answer_not_a_partial_one(monkeypatch):
    """With --open a host without open ports is left out of the report, so "no hosts" is Nmap's complete
    answer for a dead or fully filtered target: a note, but not partial results."""
    fake_nmap(monkeypatch, NMAP_HEAD + '<runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>')
    run = nmap_run("nmrev0000003", target="10.10.20.5")
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "completed" and stage.partial is False
    assert stage.error == "Host appears down or fully filtered: no open ports in the probed range."
    assert summarize(run, 0).partial is False


# --- Hosts that hit --host-timeout ----------------------------------------------------------------

def test_host_timeout_note_names_the_hosts_and_marks_the_stage_partial(monkeypatch):
    """A host that hit --host-timeout has no port table at all, so the note says its ports are missing and
    names it, and the stage is partial. Before the fix the note read "their results are partial"."""
    fake_nmap(monkeypatch, NMAP_HEAD + HOST_WITH_PORTS + TIMED_OUT_HOST + "</nmaprun>")
    run = nmap_run("nmrev0000004")
    context: dict = {}
    stage = run_stage_handler(hybrid.stage_port_scan, run, context)
    assert stage.status == "completed" and stage.partial is True
    assert stage.error == ("1 host(s) hit the 24s host timeout, so nmap reported no ports for them: 10.10.20.9. "
                           "Increase the time budget or reduce top_ports.")
    assert [p.port for p in run.ports] == [22, 80]
    assert context["hosts_up"] == 2  # the host with ports plus the timed-out host, as the stage hands it on
    summary = summarize(run, context["hosts_up"])
    assert summary.hosts_up == 2 and summary.partial is True


def test_scan_where_every_host_timed_out_fails_and_names_the_host(monkeypatch):
    """No open port and every host given up on: the stage fails (not partial) and says which host."""
    fake_nmap(monkeypatch, NMAP_HEAD + TIMED_OUT_HOST + "</nmaprun>")
    stage = run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrev0000005", target="10.10.20.9"))
    assert stage.status == "failed" and stage.partial is False
    assert stage.error.startswith("nmap gave up on 10.10.20.9 after 24s (host timeout) without finding an open port.")


def test_host_timeout_note_shows_at_most_five_hosts(monkeypatch):
    """A note about a large range stays readable: five host labels, then "and N more"."""
    timed_out = "".join(f'<host timedout="true"><status state="up"/><address addr="10.10.20.{n}" addrtype="ipv4"/>'
                        "</host>" for n in range(20, 28))
    fake_nmap(monkeypatch, NMAP_HEAD + HOST_WITH_PORTS + timed_out + "</nmaprun>")
    stage = run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrev0000006"))
    assert "8 host(s) hit the 24s host timeout" in stage.error
    assert "10.10.20.20, 10.10.20.21, 10.10.20.22, 10.10.20.23, 10.10.20.24 and 3 more." in stage.error
    assert "10.10.20.25" not in stage.error


def test_stage_notes_give_the_time_budget_advice_once(monkeypatch):
    """Stopped at the time limit and a host timed out: both are reported, the advice appears once, and the
    "appears down" note never accompanies open ports."""
    cut_off = NMAP_HEAD + HOST_WITH_PORTS + TIMED_OUT_HOST + '<host><status state="up"/><addr'
    fake_nmap(monkeypatch, cut_off, timed_out=True)
    stage = run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrev0000007"))
    assert stage.status == "completed" and stage.partial is True
    assert "stopped at the 30s stage time limit" in stage.error and "10.10.20.9" in stage.error
    assert stage.error.count("Increase the time budget or reduce top_ports.") == 1
    assert "Host appears down" not in stage.error


def test_nmap_parser_lists_the_hosts_that_hit_the_host_timeout():
    """The parser keeps the label of every timed-out host (name and address when Nmap resolved one)."""
    slow = ('<host timedout="true"><status state="up"/><address addr="10.10.20.10" addrtype="ipv4"/>'
            '<hostnames><hostname name="slow.lab.example.edu"/></hostnames></host>')
    result = parsers.parse_nmap_xml_full(NMAP_HEAD + HOST_WITH_PORTS + TIMED_OUT_HOST + slow + "</nmaprun>")
    assert result.timed_out_hosts == ["10.10.20.9", "slow.lab.example.edu (10.10.20.10)"]
    assert result.hosts_timed_out == 2 and result.hosts_up == 3 and result.truncated is False
    assert parsers.parse_nmap_xml_full(NMAP_HEAD + HOST_WITH_PORTS + "</nmaprun>").timed_out_hosts == []


# --- Host names that resolve only to IPv6 ---------------------------------------------------------

@pytest.mark.parametrize("families,expects_v6", [
    ({socket.AF_INET6}, True),
    ({socket.AF_INET, socket.AF_INET6}, False),
    ({socket.AF_INET}, False),
    (set(), False),
], ids=["ipv6-only", "dual-stack", "ipv4-only", "unresolvable"])
def test_hostname_gets_nmap_v6_flag_only_when_it_resolves_to_ipv6_alone(monkeypatch, families, expects_v6):
    """Nmap resolves a name over IPv4 unless told otherwise, so an IPv6-only name used to fail as unresolvable.
    A dual-stack name is scanned over IPv4, and a name that does not resolve is left to Nmap to report."""
    fake_nmap(monkeypatch, NMAP_HEAD + IPV6_HOST + "</nmaprun>")
    looked_up: list[str] = []
    monkeypatch.setattr(hybrid, "_address_families", lambda hostname: looked_up.append(hostname) or set(families))
    run = nmap_run("nmrev0000008", target="v6.lab.example")
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert looked_up == ["v6.lab.example"] and stage.status == "completed"
    assert (" -6 " in stage.command) is expects_v6 and stage.command.endswith("-oX - v6.lab.example")
    assert any("resolves to IPv6 addresses only, scanning with -6" in line for line in run.log) is expects_v6


@pytest.mark.parametrize("target,expects_v6", [
    ("10.10.20.5", False), ("10.10.20.0/24", False), ("2001:db8::5", True), ("2001:db8::/120", True),
])
def test_addresses_and_blocks_never_consult_the_resolver(monkeypatch, target, expects_v6):
    """Only a host name needs a lookup; addresses and blocks decide the flag by their syntax."""
    fake_nmap(monkeypatch, NMAP_HEAD + IPV6_HOST + "</nmaprun>")
    forbid_lookups(monkeypatch)
    stage = run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrev0000009", target=target))
    assert stage.status == "completed" and (" -6 " in stage.command) is expects_v6


def test_simulated_runs_never_resolve_names_or_add_v6(monkeypatch):
    """Simulation touches neither the network nor the resolver, and records a host name's command without -6. An
    IPv6 address or block is IPv6 by its syntax alone, so its simulated command carries -6 where a live run puts it,
    and an IPv4 block's does not."""
    forbid_lookups(monkeypatch)
    monkeypatch.setattr(hybrid, "run_command", lambda command, timeout: pytest.fail("a scanner was started"))
    run = nmap_run("nmrev0000010", target="v6.lab.example", mode="simulated")
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "simulated" and "-6" not in stage.command
    assert stage.command.startswith("nmap -sV") and stage.command.endswith("v6.lab.example  (simulated)")
    for target, flag in (("2001:db8::5", " -6"), ("2001:db8::/120", " -6"), ("10.10.20.0/24", "")):
        stage = run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrev0000010", target=target, mode="simulated"))
        assert stage.status == "simulated" and stage.command.startswith("nmap -sV -Pn -T4 --open --top-ports "), target
        assert stage.command.endswith(f" --host-timeout 24s{flag} -oX - {target}  (simulated)"), stage.command


def test_address_families_come_from_getaddrinfo_and_a_failed_lookup_is_empty(monkeypatch):
    """_address_families() asks getaddrinfo for TCP endpoints and turns a resolver error into an empty set."""
    seen: list[tuple] = []

    def getaddrinfo(host, port, *args, **kwargs):
        seen.append((host, port, kwargs.get("proto")))
        return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::5", 0, 0, 0)),
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::6", 0, 0, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    assert hybrid._address_families("v6.lab.example") == {socket.AF_INET6}
    assert hybrid._scan_over_ipv6("v6.lab.example") is True
    assert seen == [("v6.lab.example", None, socket.IPPROTO_TCP)] * 2  # one lookup per call

    def failing(host, port, *args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", failing)
    assert hybrid._address_families("nohost.invalid") == set()
    assert hybrid._scan_over_ipv6("nohost.invalid") is False
    assert hybrid._scan_over_ipv6("::1") is True and hybrid._scan_over_ipv6("10.10.20.0/24") is False


# --- The web stages and the run-level flag --------------------------------------------------------

def test_web_stages_are_partial_when_urls_are_skipped_or_produce_nothing(monkeypatch):
    """WhatWeb is partial when the run deadline leaves URLs unprobed; Nikto also when it produced nothing for a
    URL it was given, since that URL was not examined."""
    context: dict = {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}

    def whatweb(command, timeout):
        write_whatweb_report(command)
        context["deadline"] = time.monotonic() + 1  # the budget runs out after the first URL
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", whatweb)
    run = web_run("nmrev0000011")
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, context, stage_index=1)
    assert stage.status == "completed" and stage.partial is True
    assert stage.error == "1 URL(s) skipped because the time budget ran out."
    assert [w.reachable for w in run.web] == [True]

    calls: list[list[str]] = []

    def nikto(command, timeout):
        calls.append(command)
        if len(calls) == 1:
            with open(report_path(command), "w", encoding="utf-8") as fh:
                fh.write(json.dumps([{"host": "10.10.20.5", "vulnerabilities":
                                      [{"msg": "X-Frame-Options header is not present.", "url": "/"}]}]))
            return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)
        return CommandResult(command=command, exit_code=None, stdout="", stderr="", duration_seconds=25,
                             timed_out=True)

    monkeypatch.setattr(hybrid, "run_command", nikto)
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, {"web_ports": WEB_TARGETS,
                                                                "deadline": time.monotonic() + 100}, stage_index=2)
    assert stage.status == "completed" and stage.partial is True
    assert stage.error == "1 of 2 URL(s) failed: http://10.10.20.5:8080: timed out."
    assert len(run.vulns) == 1
    assert summarize(run).partial is True

    # Nikto that printed only its banner and error lines (no report file) examined nothing: the URL is a failure
    # with Nikto's own reason, not an examined URL with zero findings, and alone it fails the stage.
    banner_only = ("- Nikto v2.1.6\n---------------------------------------------------------------------------\n"
                   "+ ERROR: Cannot resolve hostname 'x'\n+ 0 host(s) tested\n")
    monkeypatch.setattr(hybrid, "run_command", lambda command, timeout: CommandResult(
        command=command, exit_code=1, stdout=banner_only, stderr="", duration_seconds=0.2))
    run = web_run("nmrev0000013")
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, {"web_ports": WEB_TARGETS[:1],
                                                                "deadline": time.monotonic() + 100}, stage_index=2)
    assert stage.status == "failed" and run.vulns == []
    assert stage.error == "Nikto produced no results for any URL: http://10.10.20.5: ERROR: Cannot resolve hostname 'x'"
    # When the budget then runs out before the next URL, the reason says that URL was never tried.
    short = {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}

    def banner_then_out_of_time(command, timeout):
        short["deadline"] = time.monotonic() + 1
        return CommandResult(command=command, exit_code=1, stdout=banner_only, stderr="", duration_seconds=0.2)

    monkeypatch.setattr(hybrid, "run_command", banner_then_out_of_time)
    run = web_run("nmrev0000019")
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, short, stage_index=2)
    assert stage.status == "failed" and stage.error.endswith("; 1 URL(s) skipped because the time budget ran out")
    clean = "- Nikto v2.1.6\n+ Target IP: 10.10.20.5\n+ Start Time: 2026-11-07\n+ End Time: 2026-11-07\n+ 1 host(s) tested\n"
    monkeypatch.setattr(hybrid, "run_command", lambda command, timeout: CommandResult(
        command=command, exit_code=0, stdout=clean, stderr="", duration_seconds=0.2))
    run = web_run("nmrev0000014")
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, {"web_ports": WEB_TARGETS[:1],
                                                                "deadline": time.monotonic() + 100}, stage_index=2)
    assert stage.status == "completed" and stage.partial is False and stage.error is None and run.vulns == []

    def nikto_once(run_id, fake):
        monkeypatch.setattr(hybrid, "run_command", fake)
        run = web_run(run_id)
        stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, {"web_ports": WEB_TARGETS[:1],
                                                                    "deadline": time.monotonic() + 100}, stage_index=2)
        return run, stage

    # A Nikto killed at its time limit examined only part of the URL: with nothing but its header printed it is a
    # failure, and with findings printed they are kept but the URL is not recorded as completely examined.
    header = "- Nikto v2.5.0\n+ Target IP: 10.10.20.5\n+ Target Port: 80\n+ Start Time: 2026-11-10\n"

    def killed(stdout):
        return lambda command, timeout: CommandResult(command=command, exit_code=None, stdout=stdout, stderr="",
                                                      duration_seconds=25, timed_out=True)

    run, stage = nikto_once("nmrev0000015", killed(header))
    assert stage.status == "failed" and run.vulns == []
    assert stage.error.startswith("Nikto produced no results for any URL: http://10.10.20.5: stopped at its ")
    run, stage = nikto_once("nmrev0000016", killed(header + "+ /admin/: Admin login page found.\n"))
    assert stage.status == "completed" and stage.partial is True and len(run.vulns) == 1
    assert stage.error.startswith("1 URL(s) were not examined completely, so findings may be missing: "
                                  "http://10.10.20.5: stopped at its ")

    # Nikto that gave up after too many errors still writes its JSON report: an empty report is no clean result,
    # and a report with findings is kept but marked as not examined completely.
    gave_up = header + ("+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream\n"
                        "+ Scan terminated: 20 error(s) and 0 item(s) reported on remote host\n")

    def report_and(stdout, findings):
        def fake(command, timeout):
            with open(report_path(command), "w", encoding="utf-8") as fh:
                fh.write(json.dumps([{"host": "10.10.20.5", "vulnerabilities": findings}]))
            return CommandResult(command=command, exit_code=1, stdout=stdout, stderr="", duration_seconds=0.2)
        return fake

    run, stage = nikto_once("nmrev0000017", report_and(gave_up, []))
    assert stage.status == "failed" and run.vulns == [] and "Error limit (20) reached" in stage.error
    run, stage = nikto_once("nmrev0000018", report_and(gave_up, [{"msg": "Retrieved x-powered-by header: PHP/7.4.33",
                                                                    "url": "/"}]))
    assert stage.status == "completed" and stage.partial is True and len(run.vulns) == 1
    assert "Error limit (20) reached" in stage.error and summarize(run).partial is True

    # "No web server found" is Nikto's status line for a closed port, not a finding.
    no_server = "- Nikto v2.5.0\n+ No web server found on 10.10.20.5:80\n+ 0 host(s) tested\n"
    run, stage = nikto_once("nmrev0000019", lambda command, timeout: CommandResult(
        command=command, exit_code=1, stdout=no_server, stderr="", duration_seconds=0.1))
    assert stage.status == "failed" and run.vulns == []
    assert stage.error == "Nikto produced no results for any URL: http://10.10.20.5: No web server found on 10.10.20.5:80"

    # Nikto that reached its own -maxtime ran its tests for the whole slice: partial, even without findings.
    maxtime = header + ("+ ERROR: Host maximum execution time of 45 seconds reached\n"
                        "+ Scan terminated: 0 error(s) and 0 item(s) reported on remote host\n")
    run, stage = nikto_once("nmrev0000020", lambda command, timeout: CommandResult(
        command=command, exit_code=1, stdout=maxtime, stderr="", duration_seconds=45))
    assert stage.status == "completed" and stage.partial is True and run.vulns == []
    assert "Host maximum execution time of 45 seconds reached" in stage.error

    # A budget that ran out before the first URL examined nothing: the stage fails instead of looking clean.
    run = web_run("nmrev0000021")
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, {"web_ports": WEB_TARGETS,
                                                                "deadline": time.monotonic() - 1}, stage_index=2)
    assert stage.status == "failed" and stage.error == "The time budget ran out before Nikto could scan any of the 2 URL(s)."
    run = web_run("nmrev0000022")
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, {"web_ports": WEB_TARGETS,
                                                                  "deadline": time.monotonic() - 1}, stage_index=1)
    assert stage.status == "failed" and stage.error == "The time budget ran out before WhatWeb could probe any of the 2 URL(s)."

    # A web stage starts no URL after its slot ends (simulated clock, 180 s budget: the slots end at 99, 135 and
    # 180 s). Eight web services whose WhatWeb probes answer and then hang until the per-URL limit used to keep
    # WhatWeb busy for 80 s against its 36 s share, so after a full Nmap stage Nikto had no time left at all.
    class Clock:
        """time.monotonic() for the pipeline: it moves only when a fake scanner says that it took time."""
        now = 1000.0

        def monotonic(self) -> float:
            return self.now

        @staticmethod
        def sleep(seconds: float) -> None:
            time.sleep(seconds)

    clock = Clock()
    ports = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="http"/></port>'
                    for p in (80, *range(8080, 8087)))
    eight_web = (NMAP_HEAD + '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/><ports>'
                 + ports + "</ports></host></nmaprun>")
    probes: list[float] = []
    scans: list[tuple[float, str]] = []
    nmap_seconds = [99]  # a full Nmap stage first

    def scanners(command, timeout):
        tool = command[0].rsplit("/", 1)[-1]
        if tool == "nmap":
            clock.now += nmap_seconds[0]
            return CommandResult(command=command, exit_code=0, stdout=eight_web, stderr="", duration_seconds=99)
        if tool == "whatweb":
            probes.append(clock.now)
            write_whatweb_report(command)  # the service answers, then the probe hangs until it is stopped
            clock.now += timeout
            return CommandResult(command=command, exit_code=None, stdout="", stderr="", duration_seconds=timeout,
                                 timed_out=True)
        scans.append((clock.now, command[command.index("-maxtime") + 1]))
        with open(report_path(command), "w", encoding="utf-8") as fh:
            fh.write(json.dumps([{"host": "10.10.20.5", "vulnerabilities":
                                  [{"msg": "X-Frame-Options header is not present.", "url": "/"}]}]))
        clock.now += timeout - 5  # Nikto stops by itself at its -maxtime
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=timeout - 5)

    fake_nmap(monkeypatch, "")  # every scanner "installed" and no name lookup; the calls go to scanners()
    monkeypatch.setattr(hybrid, "run_command", scanners)
    monkeypatch.setattr(hybrid, "time", clock)
    run = execute_and_wait(ExecuteRequest(target="10.10.20.5", authorized=True), ["nmap", "whatweb", "nikto"],
                           budget=180)
    whatweb, nikto = run.stages[1], run.stages[2]
    # WhatWeb probes three URLs at 10 s each; at 129 s only 6 s of its slot are left, so the other five wait.
    assert [round(t - 1000) for t in probes] == [99, 109, 119]
    assert whatweb.status == "completed" and whatweb.partial is True
    assert "5 URL(s) skipped because the time budget ran out" in whatweb.error
    # Nikto starts inside WhatWeb's slot, so its own share is intact: two of the three URLs at 20 s each.
    assert [(round(t - 1000), maxtime) for t, maxtime in scans] == [(129, "20s"), (149, "20s")]
    assert nikto.status == "completed" and nikto.partial is True and len(run.vulns) == 2
    assert "1 URL(s) skipped because the time budget ran out" in nikto.error
    assert run.status == "completed" and run.summary.partial is True
    # With Nmap done after 50 s, WhatWeb may use the 49 s that Nmap left over: all eight URLs are probed by 130 s,
    # inside its slot (135 s), and Nikto again starts with its own share intact.
    clock.now, nmap_seconds[0] = 1000.0, 50
    probes.clear()
    scans.clear()
    run = execute_and_wait(ExecuteRequest(target="10.10.20.5", authorized=True), ["nmap", "whatweb", "nikto"],
                           budget=180)
    assert [round(t - 1000) for t in probes] == [50, 60, 70, 80, 90, 100, 110, 120]
    assert "skipped" not in run.stages[1].error
    assert [(round(t - 1000), maxtime) for t, maxtime in scans] == [(130, "20s"), (150, "20s")]
    assert "6 URL(s) skipped because the time budget ran out" in run.stages[2].error


def test_an_unresponsive_url_is_a_result_not_a_gap(monkeypatch):
    """A URL that gives no HTTP response is recorded as unreachable; that is an answer, so the stage is complete."""
    def whatweb(command, timeout):
        if command[-1].endswith(":8080"):
            return CommandResult(command=command, exit_code=1, stdout="", stderr="ERROR Opening: connection refused",
                                 duration_seconds=0.1)
        write_whatweb_report(command)
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", whatweb)
    run = web_run("nmrev0000012")
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run,
                              {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}, stage_index=1)
    assert stage.status == "completed" and stage.partial is False
    assert "1 of 2 URL(s) did not respond" in stage.error
    assert [w.reachable for w in run.web] == [True, False]
    assert summarize(run).partial is False


def test_documents_without_the_partial_fields_load_as_complete():
    """Runs saved by earlier versions have no partial flags; they load as complete instead of failing."""
    run = make_run(id="nmrev0000013", stages=[StageResult(stage="port_scan", tool="nmap", status="completed")])
    document = json.loads(run.model_dump_json())
    del document["summary"]["partial"], document["stages"][0]["partial"]
    loaded = Run.model_validate(document)
    assert loaded.summary.partial is False and loaded.stages[0].partial is False


def test_simulated_runs_are_never_partial():
    """Synthetic results are complete by construction: no flag, no notice, no comparison note."""
    run = execute_and_wait(ExecuteRequest(target="127.0.0.1", authorized=True, simulate=True),
                           ["nmap", "whatweb", "nikto"])
    try:
        assert run.status == "completed" and run.summary.partial is False
        assert [s.partial for s in run.stages] == [False, False, False]
        assert compare_runs(run, run).note is None
        assert "Partial results" not in render_markdown(run) and "Partial results" not in render_html(run)
        assert render_csv(run).splitlines()[1].endswith(",complete,simulated")
    finally:
        storage.delete_run(run.id)


def test_api_lists_the_partial_flag_and_the_comparison_note(client):
    """GET /api/runs carries summary.partial for every run, GET /api/compare carries the warning note, and the
    report downloads carry the marker."""
    note = ("nmap was stopped at the 99s stage time limit: its output was truncated after 1 host(s) and the rest "
            "of the target was not scanned, so results are partial. Increase the time budget or reduce top_ports.")
    partial = make_run(id="nmrevapi0001", target="10.10.20.0/24", status="completed", tools=["nmap"],
                       ports=[PortFinding(host="10.10.20.5", port=22, service="ssh")],
                       stages=[StageResult(stage="port_scan", tool="nmap", status="completed", partial=True,
                                           error=note)])
    partial.summary = summarize(partial, 1)
    complete = make_run(id="nmrevapi0002", target="10.10.20.0/24", status="completed", tools=["nmap"],
                        ports=[PortFinding(host="10.10.20.5", port=22, service="ssh"),
                               PortFinding(host="10.10.20.6", port=80, service="http")],
                        stages=[StageResult(stage="port_scan", tool="nmap", status="completed")])
    complete.summary = summarize(complete, 2)
    storage.save_run(partial)
    storage.save_run(complete)
    try:
        listed = {item["id"]: item for item in client.get("/api/runs").json()}
        assert listed[partial.id]["summary"]["partial"] is True
        assert listed[complete.id]["summary"]["partial"] is False
        diff = client.get("/api/compare", params={"base": complete.id, "other": partial.id}).json()
        assert diff["note"].startswith("The other run has partial results")
        assert [p["port"] for p in diff["ports_removed"]] == [80] and diff["other"]["summary"]["partial"] is True
        same = client.get("/api/compare", params={"base": complete.id, "other": complete.id}).json()
        assert same["note"] is None
        csv_text = client.get(f"/api/runs/{partial.id}/report", params={"format": "csv"}).text
        assert csv_text.splitlines()[1].endswith(",partial,live")
        html = client.get(f"/api/runs/{partial.id}/report", params={"format": "html"}).text
        assert "<b>Partial results.</b> nmap: nmap was stopped at the 99s stage time limit" in html
    finally:
        storage.delete_run(partial.id)
        storage.delete_run(complete.id)


def test_dashboard_shows_the_partial_pill_and_the_comparison_warning():
    """The run header, both run tables, the comparison header and the Summary tab show partial results, and
    the completion toast says so."""
    js = (BASE_DIR / "dashboard" / "app.js").read_text(encoding="utf-8")
    assert js.count("partialPill(") >= 6  # definition, recent runs, runs table, run header and its patch, compare
    assert js.count("partialNoticeHtml(") >= 3  # definition, the Summary tab and its patch
    assert "c.note" in js and "with partial results" in js
    # The header pill and the Summary-tab notice are repainted when the flag appears after the stages settled.
    assert js.count("isPartial(prev) !== isPartial(run)") == 2
    # A failed run shows no partial pill: its status already says the results are unusable.
    assert 'run.status === "completed" && run.summary && run.summary.partial' in js


# --- Failed stages, failed runs and interrupted runs ------------------------------------------------

def test_a_failed_later_stage_marks_the_completed_run_partial_in_every_view():
    """A run completes when a later stage fails, but that stage examined nothing: the run is partial in the
    summary, the CSV, the reports and the comparison, not "complete". Before the fix only the stage said so."""
    error = "Nikto produced no results for any URL: http://10.10.20.5: timed out"
    run = make_run(id="nmrevfail001", target="10.10.20.5", status="completed", tools=["nmap", "nikto"],
                   ports=[PortFinding(host="10.10.20.5", port=80, service="http", is_web=True)],
                   stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                           StageResult(stage="web_vuln_scan", tool="nikto", status="failed", error=error)],
                   error=f"nikto: {error}")
    run.summary = summarize(run, 1)
    assert hybrid._final_outcome(run.stages) == ("completed", f"nikto: {error}")
    assert run.summary.partial is True and coverage_label(run) == "partial"
    assert render_csv(run).splitlines()[1].endswith(",partial,live")
    markdown = render_markdown(run)
    assert "**Status:** completed (partial results)" in markdown
    assert "> **Partial results.** nikto: Nikto produced no results for any URL" in markdown
    # Each stage note ends with a full stop, so two notes never run together.
    two = run.model_copy(deep=True)
    two.stages[0].partial, two.stages[0].error = True, "1 URL(s) answered but the probe was stopped early: x"
    assert "stopped early: x. nikto: " in render_markdown(two)
    assert "<b>Partial results.</b> nikto: Nikto produced no results for any URL" in render_html(run)
    full = make_run(id="nmrevfull001", target="10.10.20.5", status="completed", tools=["nmap", "nikto"],
                    ports=run.ports,
                    vulns=[VulnFinding(url="http://10.10.20.5", severity="low",
                                       description="X-Frame-Options header is not present.")],
                    stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                            StageResult(stage="web_vuln_scan", tool="nikto", status="completed")])
    full.summary = summarize(full, 1)
    diff = compare_runs(full, run)
    assert len(diff.vulns_removed) == 1 and diff.note.startswith("The other run has partial results")
    # A custom tool is not part of the findings: its failure is named in the run's error but never makes the run
    # partial, and the partial notice leaves it out.
    custom_failed = StageResult(stage="custom_tool", tool="hdrcheck", status="failed", error="hdrcheck is not installed")
    clean = full.model_copy(deep=True)
    clean.stages.append(custom_failed)
    assert hybrid._final_outcome(clean.stages)[1] == "hdrcheck: hdrcheck is not installed"
    clean.summary = summarize(clean, 1)
    assert clean.summary.partial is False and coverage_label(clean) == "complete"
    two.stages.append(custom_failed)
    notice = next(line for line in render_markdown(two).splitlines() if line.startswith("> **Partial results.**"))
    assert "hdrcheck" not in notice
    cut_short = full.model_copy(deep=True)
    cut_short.stages.append(StageResult(stage="custom_tool", tool="hdrcheck", status="completed", partial=True,
                                        error="1 call(s) were stopped at their time limit"))
    assert summarize(cut_short, 1).partial is False


def test_a_failed_run_is_not_partial_but_its_views_say_it_failed():
    """A run whose first stage failed is "failed", not partial: the reports open with the run error, the CSV
    coverage says failed, and the comparison says the run failed."""
    error = "nmap could not resolve or reach 'nohost.invalid' (0 hosts scanned)."
    run = make_run(id="nmrevfail002", target="nohost.invalid", status="failed", tools=["nmap"],
                   stages=[StageResult(stage="port_scan", tool="nmap", status="failed", error=error)], error=error)
    run.summary = summarize(run, 0)
    assert run.summary.partial is False and coverage_label(run) == "failed"
    assert "**Status:** failed  " in render_markdown(run) and "(partial results)" not in render_markdown(run)
    assert "> **Run failed.** nmap could not resolve or reach" in render_markdown(run)
    assert "<b>Run failed.</b> nmap could not resolve or reach" in render_html(run)
    good = make_run(id="nmrevgood002", target="nohost.invalid", status="completed", tools=["nmap"],
                    ports=[PortFinding(host="10.10.20.5", port=22, service="ssh")],
                    stages=[StageResult(stage="port_scan", tool="nmap", status="completed")])
    good.summary = summarize(good, 1)
    assert compare_runs(run, good).note.startswith("The base run failed (see the stage notes), so anything missing from it")
    assert compare_runs(run, run).note.startswith("Both runs failed")
    running = make_run(id="nmrevrun0002", status="running", tools=["nmap"],
                       stages=[StageResult(stage="port_scan", tool="nmap", status="running")])
    assert coverage_label(running) == "in progress"
    assert compare_runs(running, good).note.startswith("The base run is still executing")
    assert compare_runs(run, running).note.startswith("The base run failed and the other run is still executing")


def test_an_interrupted_run_exports_failed_coverage_not_complete():
    """A run that a server restart marked failed keeps its salvaged ports; the CSV rows say "failed" and the
    comparison warns, so the ports it never reached are not read as closed."""
    interrupted = make_run(id="nmrevstale01", target="10.10.20.0/24", status="running", tools=["nmap", "whatweb"],
                           started_at=datetime.now(timezone.utc),
                           ports=[PortFinding(host="10.10.20.5", port=22, service="ssh")],
                           stages=[StageResult(stage="port_scan", tool="nmap", status="completed", partial=True,
                                               error="nmap was stopped at the 99s stage time limit."),
                                   StageResult(stage="web_fingerprint", tool="whatweb", status="running")])
    storage.save_run(interrupted)
    try:
        assert storage.fail_stale_runs() >= 1
        run = storage.get_run(interrupted.id)
        assert run.status == "failed" and run.stages[1].status == "failed" and run.ports == interrupted.ports
        assert coverage_label(run) == "failed" and render_csv(run).splitlines()[1].endswith(",failed,live")
        assert "> **Run failed.** The server restarted before this run finished." in render_markdown(run)
        full = make_run(id="nmrevfull002", target="10.10.20.0/24", status="completed", tools=["nmap"],
                        ports=[*run.ports, PortFinding(host="10.10.20.6", port=443, service="https")],
                        stages=[StageResult(stage="port_scan", tool="nmap", status="completed")])
        full.summary = summarize(full, 2)
        diff = compare_runs(run, full)
        assert [p.port for p in diff.ports_added] == [443] and diff.note.startswith("The base run failed")
    finally:
        storage.delete_run(interrupted.id)


def test_a_whatweb_probe_stopped_at_its_limit_or_unable_to_start_is_a_gap(monkeypatch):
    """A probe killed at its per-URL limit, or a WhatWeb process that could not start, examined nothing: the URL
    is recorded as unreachable (so Nikto skips it) but the stage is partial. Before the fix both counted as
    "did not respond" and the run was labelled complete."""
    def stopped(command, timeout):
        if command[-1].endswith(":8080"):
            return CommandResult(command=command, exit_code=None, stdout="", stderr="", duration_seconds=15,
                                 timed_out=True)
        write_whatweb_report(command)
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", stopped)
    run = web_run("nmrevww00001")
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run,
                              {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}, stage_index=1)
    assert stage.status == "completed" and stage.partial is True
    assert "http://10.10.20.5:8080: timed out after 15s" in stage.error
    assert [w.reachable for w in run.web] == [True, False] and summarize(run).partial is True

    def answered_then_killed(command, timeout):
        write_whatweb_report(command)  # WhatWeb logged the response before the kill
        if command[-1].endswith(":8080"):
            return CommandResult(command=command, exit_code=None, stdout="", stderr="", duration_seconds=15,
                                 timed_out=True)
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "run_command", answered_then_killed)
    run = web_run("nmrevww00003")
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run,
                              {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}, stage_index=1)
    # The URL answered, so it is reachable (Nikto will scan it) and is not reported as "did not respond"; the
    # fingerprint may still be incomplete, so the stage stays partial and says what happened.
    assert stage.status == "completed" and stage.partial is True
    assert stage.error == ("1 URL(s) answered but the probe was stopped early, so the fingerprint may be "
                           "incomplete: http://10.10.20.5:8080: probe stopped at its 15s limit after a response.")
    assert [w.reachable for w in run.web] == [True, True] and summarize(run).partial is True

    def vanished(command, timeout):
        if command[-1].endswith(":8080"):
            raise FileNotFoundError(2, "No such file or directory", command[0])
        write_whatweb_report(command)
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "run_command", vanished)
    run = web_run("nmrevww00002")
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run,
                              {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}, stage_index=1)
    assert stage.status == "completed" and stage.partial is True
    assert "Could not start whatweb" in stage.error and [w.reachable for w in run.web] == [True]
    # A probe that never started says nothing about the URL: it is "could not be probed", not "did not respond".
    assert stage.error.startswith("1 URL(s) could not be probed: http://10.10.20.5:8080: Could not start whatweb")
    assert "did not respond" not in stage.error

    monkeypatch.setattr(hybrid, "run_command", lambda command, timeout: (_ for _ in ()).throw(
        FileNotFoundError(2, "No such file or directory", command[0])))
    run = web_run("nmrevww00004")
    context = {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, context, stage_index=1)
    assert stage.status == "failed" and stage.error.startswith("WhatWeb could not probe any web service: ")
    # WhatWeb ran but no URL answered it (none could even be probed): Nikto then has nothing to scan, rather
    # than falling back to every web port as it does when WhatWeb is not part of the workflow.
    assert context["fingerprinted"] is True and run.web == []
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, context, stage_index=2)
    # The reason says that WhatWeb never got to probe anything, not that no web service was reachable.
    assert stage.status == "skipped"
    assert stage.error == "WhatWeb could not probe any web service, so no URL is known to answer; nothing to scan."

    # The first URL gave no answer and the budget ran out before the second: the reason says the second was
    # never probed, so the run does not read as "no web service on the standard ports".
    def silent_then_out_of_time(command, timeout):
        budget["deadline"] = time.monotonic() + 1
        return CommandResult(command=command, exit_code=1, stdout="", stderr="connection refused",
                             duration_seconds=0.1)

    budget = {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}
    monkeypatch.setattr(hybrid, "run_command", silent_then_out_of_time)
    run = web_run("nmrevww00006")
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, budget, stage_index=1)
    assert stage.status == "failed" and stage.error.startswith(hybrid.WHATWEB_NO_RESPONSE + " it probed: ")
    assert stage.error.endswith("1 URL(s) skipped because the time budget ran out")
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, budget, stage_index=2)
    assert stage.status == "skipped"
    assert stage.error == "No web service answered WhatWeb, and 1 URL(s) could not be probed; nothing to scan."

    def shutdown_after_answer(command, timeout):
        write_whatweb_report(command)  # the response was logged, then the server's shutdown killed WhatWeb
        if command[-1].endswith(":8080"):
            return CommandResult(command=command, exit_code=None, stdout="", stderr="", duration_seconds=2,
                                 interrupted=True)
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    monkeypatch.setattr(hybrid, "run_command", shutdown_after_answer)
    run = web_run("nmrevww00005")
    context = {"web_ports": WEB_TARGETS, "deadline": time.monotonic() + 100}
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, context, stage_index=1)
    assert "http://10.10.20.5:8080: answered, then whatweb was stopped: the server is shutting down" in stage.error
    assert "did not respond" not in stage.error and [w.reachable for w in run.web] == [True, True]
    assert context.get("interrupted") is True


def test_every_fake_scanner_helper_keeps_the_suite_off_the_resolver(monkeypatch):
    """The older test helpers patch the resolver too, so no module's host-name scan asks a real DNS server
    (one did, for nohost.invalid, until the review caught it)."""
    import tests.test_adversarial_qa as adversarial
    import tests.test_review_fixes_round3_backend as round3
    from tests.test_api import fake_scanner

    def tripwire(*args, **kwargs):
        raise AssertionError("socket.getaddrinfo was called")

    monkeypatch.setattr(socket, "getaddrinfo", tripwire)
    xml = NMAP_HEAD + '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/></host></nmaprun>'

    def answer(command, timeout):
        return CommandResult(command=command, exit_code=0, stdout=xml, stderr="", duration_seconds=0.1)

    fake_scanner(monkeypatch, stdout=xml)
    assert run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrevdns0001", target="nohost.invalid")).status == "completed"
    adversarial.fake_tools(monkeypatch, answer)
    assert run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrevdns0002", target="nohost.invalid")).status == "completed"
    round3._fake_tools(monkeypatch, answer)
    assert run_stage_handler(hybrid.stage_port_scan, nmap_run("nmrevdns0003", target="nohost.invalid")).status == "completed"
