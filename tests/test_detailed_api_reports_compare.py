"""Detailed edge-case tests for run comparison (app/compare.py), the report renderers (app/reports.py), the
request guards in app/main.py and the API routers (app/routers/*.py).

Every test checks one behaviour and names it. The API is exercised through FastAPI's TestClient in simulation
mode, so no scanner is ever started and nothing leaves the machine. Importing tests.test_api first points the
app at a private .env file, a temporary data directory and the rules planner.
"""
from __future__ import annotations

import csv
import io
import json
import os
import threading
import urllib.parse
from datetime import datetime, timezone
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import hybrid, storage
from app.compare import _vuln_key, compare_runs
from app.config import ENV_FILE, settings
from app.envfile import update_env_file
from app.main import _hostname, app
from app.reports import (
    FORMATS,
    _csv_safe,
    _md_escape,
    _risk_color,
    filename,
    render,
    render_csv,
    render_html,
    render_markdown,
)
from app.routers.settings_api import PlannerTestResult, SettingsView, require_local
from app.schemas import (
    CustomTool,
    CustomToolCreate,
    CustomToolOutput,
    PortFinding,
    RunSummary,
    StageResult,
    VulnFinding,
    WebFinding,
)
from app.tools import custom
from app.tools.registry import TOOLS
from tests.test_api import CUSTOM_BODY, make_run, start_run, wait_for_run

PLAN_BODY = {"tools": ["nmap"], "objective": "Detailed test: plan a port scan of an authorized lab host."}


# --- Fixtures and helpers -------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    """One API client for the module. Its peer is "testclient", so the loopback-only settings guard is overridden."""
    app.dependency_overrides[require_local] = lambda: None
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="module")
def finished_run(client) -> dict:
    """One completed simulated three-tool run, shared by the report and comparison tests of this module."""
    resp = start_run(client, tools=["nmap", "whatweb", "nikto"], label="detailed")
    assert resp.status_code == 202, resp.text
    return wait_for_run(client, resp.json()["id"])


def finding(url: str, description: str, severity: str = "low") -> VulnFinding:
    return VulnFinding(url=url, severity=severity, description=description)


def tech_run(run_id: str, host: str = "10.10.20.5", port: int = 80, name: str = "nginx", version: str = "1.18.0",
             url: str | None = None, reachable: bool = True):
    """A run whose only web service reports one technology; every key component can be varied."""
    return make_run(id=run_id, tools=["whatweb"],
                    web=[WebFinding(url=url or f"http://{host}:{port}", host=host, port=port,
                                    technologies=[{"name": name, "version": version}], reachable=reachable)])


def rich_run(run_id: str = "rich0000001", **fields):
    """A run with ports, technologies, findings and a risk score, for comparison and report tests."""
    values = {
        "id": run_id, "mode": "simulated", "tools": ["nmap", "whatweb", "nikto"],
        "ports": [PortFinding(host="10.10.20.5", port=22, service="ssh", product="OpenSSH", version="8.9"),
                  PortFinding(host="10.10.20.5", port=80, service="http", product="nginx", version="1.18.0",
                              is_web=True)],
        "web": [WebFinding(url="http://10.10.20.5", host="10.10.20.5", port=80, status_code=200, title="Demo",
                           technologies=[{"name": "nginx", "version": "1.18.0"}, {"name": "PHP", "version": "7.4"},
                                         {"name": "HTML5"}]),
                WebFinding(url="http://10.10.20.5:8080", host="10.10.20.5", port=8080, reachable=False)],
        "vulns": [VulnFinding(url="http://10.10.20.5/", severity="low", description="X-Frame-Options missing",
                              reference="CWE-1021"),
                  VulnFinding(url="http://10.10.20.5/manager/html", severity="high",
                              description="Tomcat Manager reachable")],
        "log": ["[t] run queued", "[t] run completed in 1.0s"],
    }
    values.update(fields)
    run = make_run(**values)
    if "summary" not in fields:
        run.summary = hybrid.summarize(run)
    return run


# One custom-tool call per way a call can end and per way its output can be cut (CustomToolOutput.ended, truncated
# and run_limit), with the status the reports give it and what the CSV says about its output. The second call is a
# run saved before `ended` existed: it reads as "exited", and timed_out still means the time limit.
ELSEWHERE = "The output is in the JSON, HTML and Markdown reports."
RUN_LIMIT_TEXT = f"its limit of {custom.RUN_OUTPUT_CHARS:,} characters of custom-tool output"
CALLS = [
    ({"exit_code": 3, "stdout": "ok"}, "exit code 3", ELSEWHERE),
    ({"exit_code": None, "timed_out": True, "stdout": "partial"}, "stopped at the time limit", ELSEWHERE),
    ({"ended": "output_limit", "truncated": True, "stdout": "x" * 10},
     f"stopped for printing more than {custom.STDOUT_CHARS:,} characters", ELSEWHERE),
    ({"ended": "shutdown", "stdout": "half"}, "stopped by the server shutdown", ELSEWHERE),
    ({"ended": "not_started", "stderr": "curl was not found"}, "could not be started", ELSEWHERE),
    ({"ended": "simulated", "stdout": "[simulated] sample"}, "simulated, not started", ELSEWHERE),
    ({"exit_code": 0, "stdout": "y", "truncated": True, "run_limit": True},
     f"exit code 0; output cut: the run reached {RUN_LIMIT_TEXT}", ELSEWHERE),
    ({"exit_code": 0, "truncated": True, "run_limit": True},
     f"exit code 0; output not kept: the run had already reached {RUN_LIMIT_TEXT}", ""),
    ({"exit_code": 0}, "exit code 0", "The tool printed nothing."),
    ({"exit_code": 0, "truncated": True}, "exit code 0; output truncated",
     "Nothing printable was kept: the output was cut at a limit."),
]


def simulated_status(fields: dict, status: str) -> str:
    """The status the reports give a call of CALLS in a simulated run: one saved before `ended` existed (it reads
    "exited", with a made-up exit code or time limit) was simulated, and any other ending is shown as recorded."""
    if "ended" in fields:
        return status
    _head, cut, note = status.partition(";")
    return "simulated, not started" + cut + note


def custom_calls_run():
    """A completed run whose custom tool made the CALLS above, on http://10.10.20.5:8000, :8001 and so on."""
    tool = CustomTool(name="hdr", program="curl", args=["-sI", "{url}"], scope="url",
                      created_at=datetime.now(timezone.utc))
    return make_run(id="calls000001", tools=["nmap", "hdr"], custom_tools={"hdr": tool},
                    stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                            StageResult(stage="custom_tool", tool="hdr", status="completed")],
                    custom_outputs=[CustomToolOutput(tool="hdr", target=f"http://10.10.20.5:{8000 + k}",
                                                     command="curl -sI x", **fields)
                                    for k, (fields, _status, _where) in enumerate(CALLS)])


# --- Comparison: findings -------------------------------------------------------------------------

def test_compare_reports_new_resolved_and_unchanged_findings_separately():
    """A finding in both runs is silent, one only in the base is removed, one only in the other is added."""
    unchanged = finding("http://10.10.20.5/", "X-Frame-Options missing")
    resolved = finding("http://10.10.20.5/old", "Old issue", "medium")
    new = finding("https://10.10.20.5/", "X-Frame-Options missing")  # same text on https is another finding
    diff = compare_runs(make_run(id="cmpa0000001", vulns=[unchanged, resolved]),
                        make_run(id="cmpb0000001", vulns=[unchanged, new]))
    assert diff.vulns_added == [new] and diff.vulns_removed == [resolved]
    # A second advisory on the same URL is a new finding (ids and versions stay in the key), and a finding the
    # other run reports twice where the base reports it once counts once more, instead of being merged away.
    first = finding("http://10.10.20.5/", "Apache/2.4.49 is vulnerable to path traversal, see CVE-2021-41773.", "high")
    second = finding("http://10.10.20.5/", "Apache/2.4.50 is vulnerable to path traversal, see CVE-2021-42013.", "high")
    diff = compare_runs(make_run(id="cmpa0000002", vulns=[first]), make_run(id="cmpb0000002", vulns=[first, second]))
    assert diff.vulns_added == [second] and diff.vulns_removed == []
    diff = compare_runs(make_run(id="cmpa0000003", vulns=[unchanged]),
                        make_run(id="cmpb0000003", vulns=[unchanged, unchanged]))
    assert diff.vulns_added == [unchanged] and diff.vulns_removed == []


@pytest.mark.parametrize("left,right", [
    ("http://10.10.20.5/admin/", "http://10.10.20.5/admin"),
    ("http://10.10.20.5/admin?sid=42", "http://10.10.20.5/admin"),
    ("HTTP://10.10.20.5/Admin", "http://10.10.20.5/admin"),
], ids=["trailing-slash", "query-string", "letter-case"])
def test_finding_keys_ignore_trailing_slash_query_string_and_case(left, right):
    """Volatile parts of a URL (trailing slash, session query, letter case) do not make a finding look new."""
    assert _vuln_key(finding(left, "same text")) == _vuln_key(finding(right, "same text"))


@pytest.mark.parametrize("left,right", [
    ("Server leaks inode 12345 via ETag, size 777", "Server leaks inode 67890 via ETag, size 778"),
    ("Server may leak inodes via ETags, header found with file /, inode: 2cf6, size: 5a6d6b2ba1f9a, mtime: gzip.",
     "Server may leak inodes via ETags, header found with file /, inode: 3a01, size: 5a6d6b2bb3e4c, mtime: gzip."),
    ("  Padded message ", "Padded message"),
    ("Mixed Case Message", "mixed case message"),
], ids=["decimal-numbers", "hex-numbers", "padding", "case"])
def test_finding_keys_mask_numbers_and_ignore_padding_and_case(left, right):
    """Numbers that change on every scan (sizes, inodes, ETags in decimal, 0x or bare hex as Nikto 2.1.6+ prints
    them) and cosmetic differences are masked; advisory ids and versions are not."""
    assert _vuln_key(finding("http://10.10.20.5/", left)) == _vuln_key(finding("http://10.10.20.5/", right))
    assert _vuln_key(finding("http://10.10.20.5/", "ETag 0x1A2B found")) == \
        _vuln_key(finding("http://10.10.20.5/", "ETag 0xFFFF found"))
    assert _vuln_key(finding("http://10.10.20.5/", "See CVE-2021-41773.")) != \
        _vuln_key(finding("http://10.10.20.5/", "See CVE-2021-42013."))
    assert _vuln_key(finding("http://10.10.20.5/", "nginx/1.18.0 is outdated")) != \
        _vuln_key(finding("http://10.10.20.5/", "nginx/1.20.0 is outdated"))
    # Older Nikto wordings and per-request header values are masked too; a word after a label is not a value.
    for old, new in (("ETag header found on server, fields: 0x10f8f2 0xbc6", "ETag header found on server, "
                                                                                 "fields: 0x2aa1 0x1f0"),
                        ("inode: 2cf6, size: fe, mtime: gzip", "inode: 2cf6, size: ff, mtime: gzip"),
                        ("Uncommon header 'x-runtime' found, with contents: 0.012345",
                         "Uncommon header 'x-runtime' found, with contents: 0.000871")):
        assert _vuln_key(finding("http://10.10.20.5/", old)) == _vuln_key(finding("http://10.10.20.5/", new))
    assert _vuln_key(finding("http://10.10.20.5/", "Uncommon header 'x-powered-by' found, with contents: nginx")) != \
        _vuln_key(finding("http://10.10.20.5/", "Uncommon header 'x-powered-by' found, with contents: apache"))
    assert _vuln_key(finding("http://10.10.20.5/", "Uncommon header 'x-powered-by' found, with contents: PHP/8.1.2")) != \
        _vuln_key(finding("http://10.10.20.5/", "Uncommon header 'x-powered-by' found, with contents: PHP/8.1.3"))


@pytest.mark.parametrize("left,right", [
    (("http://10.10.20.5/", "d"), ("https://10.10.20.5/", "d")),
    (("http://10.10.20.5/a", "d"), ("http://10.10.20.5/b", "d")),
    (("http://10.10.20.5/", "d"), ("http://10.10.20.6/", "d")),
    (("http://10.10.20.5/", "header missing"), ("http://10.10.20.5/", "header present")),
], ids=["scheme", "path", "host", "wording"])
def test_finding_keys_keep_scheme_host_path_and_wording_apart(left, right):
    """A different scheme, host, path or wording is a different finding."""
    assert _vuln_key(finding(*left)) != _vuln_key(finding(*right))


def test_finding_key_falls_back_to_plain_text_for_a_malformed_url():
    """urlsplit() rejects "http://hfoo[" (unbalanced bracket); such a URL is compared as lower-cased text."""
    key = _vuln_key(finding("http://HFOO[/", "Header  Missing "))
    assert key == ("http://hfoo[", "header missing")
    assert key == _vuln_key(finding("http://hfoo[", "header missing"))


# --- Comparison: technologies, ports and risk -----------------------------------------------------

@pytest.mark.parametrize("change,differs", [
    ({}, False),
    ({"url": "http://10.10.20.5:80/?sid=9"}, False),
    ({"name": "NGINX"}, False),
    ({"version": "1.26.0"}, True),
    ({"port": 8080}, True),
    ({"host": "10.10.20.6"}, True),
    ({"name": "Apache"}, True),
], ids=["identical", "url-only", "name-case", "version", "port", "host", "name"])
def test_technology_differences_are_keyed_on_host_port_name_and_version(change, differs):
    """A technology matches on host, port, name (any case) and version; the URL it was seen at is ignored."""
    diff = compare_runs(tech_run("tcha0000001"), tech_run("tchb0000001", **change))
    assert (len(diff.tech_added), len(diff.tech_removed)) == ((1, 1) if differs else (0, 0))


def test_technology_entries_carry_url_name_and_version():
    """Added and removed technologies are reported with where they were seen, their name and their version."""
    diff = compare_runs(tech_run("tsha0000001"), tech_run("tshb0000001", version="1.26.0"))
    assert diff.tech_added == [{"url": "http://10.10.20.5:80", "name": "nginx", "version": "1.26.0"}]
    assert diff.tech_removed == [{"url": "http://10.10.20.5:80", "name": "nginx", "version": "1.18.0"}]


def test_technologies_of_unreachable_services_are_excluded_from_the_comparison():
    """A service that gave no HTTP response contributes no technologies, on either side of the comparison."""
    answered, silent = tech_run("unra0000001"), tech_run("unrb0000001", reachable=False)
    expected = [{"url": "http://10.10.20.5:80", "name": "nginx", "version": "1.18.0"}]
    assert compare_runs(answered, silent).tech_removed == expected
    assert compare_runs(silent, answered).tech_added == expected
    assert compare_runs(silent, silent).tech_added == [] and compare_runs(silent, silent).tech_removed == []


def test_port_changes_report_before_and_after_and_match_hostname_labels():
    """A port open in both runs with a new version is 'changed' (with before/after), even when one run labels
    the host "name (address)"; ports present on one side only are added or removed."""
    base = make_run(id="pta00000001", ports=[
        PortFinding(host="10.10.20.5", port=80, service="http", product="nginx", version="1.18.0"),
        PortFinding(host="10.10.20.5", port=22, service="ssh")])
    other = make_run(id="ptb00000001", ports=[
        PortFinding(host="lab.example.edu (10.10.20.5)", port=80, service="http", product="nginx", version="1.26.0"),
        PortFinding(host="10.10.20.5", port=443, service="https")])
    diff = compare_runs(base, other)
    assert [p.port for p in diff.ports_added] == [443] and [p.port for p in diff.ports_removed] == [22]
    assert diff.ports_changed == [{"host": "10.10.20.5", "port": 80, "protocol": "tcp",
                                   "before": {"service": "http", "product": "nginx", "version": "1.18.0"},
                                   "after": {"service": "http", "product": "nginx", "version": "1.26.0"}}]


def test_port_lists_are_sorted_by_port_number():
    """Added and removed ports come back in ascending port order, whatever order the scan reported."""
    scattered = [PortFinding(host="10.10.20.5", port=p, service="x") for p in (8080, 22, 443)]
    diff = compare_runs(make_run(id="srta0000001"), make_run(id="srtb0000001", ports=scattered))
    assert [p.port for p in diff.ports_added] == [22, 443, 8080]


@pytest.mark.parametrize("base_score,other_score,delta", [(20, 70, 50), (70, 20, -50), (35, 35, 0)],
                         ids=["worse", "better", "same"])
def test_risk_delta_is_other_minus_base(base_score, other_score, delta):
    """The risk delta is positive when the newer run scores higher, negative when lower, zero when equal."""
    diff = compare_runs(make_run(id="rda00000001", summary=RunSummary(risk_score=base_score)),
                        make_run(id="rdb00000001", summary=RunSummary(risk_score=other_score)))
    assert diff.risk_delta == delta


def test_a_run_compared_with_itself_reports_no_changes():
    """Comparing a run with itself yields empty difference lists and a risk delta of zero."""
    run = rich_run()
    diff = compare_runs(run, run)
    assert diff.ports_added == diff.ports_removed == diff.ports_changed == []
    assert diff.tech_added == diff.tech_removed == [] and diff.vulns_added == diff.vulns_removed == []
    assert diff.risk_delta == 0 and diff.base.id == diff.other.id == run.id
    # Only a completed run is scored, so with a run that failed or is still executing there is no delta (null),
    # whatever its summary holds, even against itself.
    for status in ("failed", "running", "queued"):
        unscored = rich_run("unsc0000001", status=status)
        assert unscored.summary.risk_score > 0, status
        assert compare_runs(run, unscored).risk_delta is None and compare_runs(unscored, run).risk_delta is None
        assert compare_runs(unscored, unscored).risk_delta is None, status


# --- Reports: CSV ---------------------------------------------------------------------------------

def test_csv_has_the_fixed_header_and_one_row_per_port_technology_and_finding():
    """The CSV starts with the 15 fixed columns and holds one row per port, per technology (or per silent web
    service) and per finding, each ending with the run's coverage and mode."""
    rows = list(csv.reader(io.StringIO(render_csv(rich_run()))))
    assert rows[0] == ["section", "host", "port", "protocol", "service", "product", "version", "url", "technology",
                       "tech_version", "severity", "description", "reference", "coverage", "mode"]
    assert [row[0] for row in rows[1:]] == ["port", "port", "web", "web", "web", "web", "vuln", "vuln"]
    assert all(len(row) == 15 and row[-2:] == ["complete", "simulated"] for row in rows[1:])
    silent = [row for row in rows if row[0] == "web" and row[7] == "http://10.10.20.5:8080"]
    assert len(silent) == 1 and silent[0][8] == ""  # a service without technologies still gets one row
    # A service that never answered says so, and a port row's description carries Nmap's extra information.
    assert silent[0][11] == "No HTTP response"
    ssh = PortFinding(host="10.10.20.5", port=22, service="ssh", extra="ssh-hostkey: 3072 RSA")
    assert list(csv.reader(io.StringIO(render_csv(rich_run(ports=[ssh])))))[1][11] == "ssh-hostkey: 3072 RSA"
    # A run without a single result row still exports one row that says how it ended.
    empty = rich_run(status="failed", error="nmap: boom", ports=[], web=[], vulns=[])
    rows = list(csv.reader(io.StringIO(render_csv(empty))))
    assert rows[1:] == [["run", empty.target, "", "", "", "", "", "", "", "", "", "nmap: boom", "", "failed",
                         "simulated"]]
    # A custom-tool call's row says how the call ended (an exit code only when the program exited by itself) and
    # which limit cut its output; it points to the other reports only when some output was kept, else says why not.
    rows = list(csv.reader(io.StringIO(render_csv(custom_calls_run()))))
    assert [row[11] for row in rows if row[0] == "tool_output"] == \
        [f"{status}. {where}".strip() for _fields, status, where in CALLS]
    # In a simulated run a call saved before `ended` existed was simulated, as the dashboard shows it, whatever exit
    # code it stored; the other endings and the notes about the output stay as they are.
    rows = list(csv.reader(io.StringIO(render_csv(custom_calls_run().model_copy(update={"mode": "simulated"})))))
    assert [row[11] for row in rows if row[0] == "tool_output"] == \
        [f"{simulated_status(fields, status)}. {where}".strip() for fields, status, where in CALLS]
    assert "No HTTP response" in render_html(rich_run())
    assert "The run failed, so no highlights were produced." in render_markdown(empty)
    assert "The run failed, so no highlights were produced." in render_html(empty)
    # Only a completed run is scored in the reports, as on the dashboard.
    assert "| not scored |" in render_markdown(empty) and "Risk score (not scored)" in render_html(empty)
    assert "/100 |" in render_markdown(rich_run())


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"], ids=["equals", "plus", "minus", "at", "tab", "cr"])
def test_csv_neutralises_every_formula_prefix(prefix):
    """A cell starting with =, +, -, @, tab or carriage return gets a leading quote, in the helper and in a report."""
    text = prefix + 'HYPERLINK("http://evil.example")'
    assert _csv_safe(text) == "'" + text
    run = rich_run(vulns=[finding("http://10.10.20.5/", text)])
    rows = list(csv.reader(io.StringIO(render_csv(run))))
    assert next(row for row in rows if row[0] == "vuln")[11] == "'" + text


def test_csv_safe_leaves_numbers_empty_cells_and_plain_text_alone():
    """Only text that starts like a formula is changed; numbers, empty cells and ordinary text pass through."""
    assert _csv_safe(80) == 80 and _csv_safe("") == "" and _csv_safe("plain text") == "plain text"
    assert _csv_safe(None) is None


def test_csv_round_trips_embedded_quotes_commas_and_newlines():
    """Quotes, commas and line breaks inside a description survive a CSV round trip unchanged."""
    tricky = 'He said "hi", twice\nthen left'
    raw = render_csv(rich_run(vulns=[finding("http://10.10.20.5/", tricky)]))
    rows = list(csv.reader(io.StringIO(raw)))
    assert next(row for row in rows if row[0] == "vuln")[11] == tricky
    assert '"He said ""hi"", twice' in raw


# --- Reports: Markdown ----------------------------------------------------------------------------

@pytest.mark.parametrize("raw,escaped", [
    ("a | b", "a \\| b"),
    ("`code`", "\\`code\\`"),
    ("*bold* _it_", "\\*bold\\* \\_it\\_"),
    ("<b>x</b>", "&lt;b&gt;x&lt;/b&gt;"),
    ("back\\slash", "back\\\\slash"),
    ("line\nbreak\ttab", "line break tab"),
    (None, ""),
], ids=["pipe", "backtick", "emphasis", "html", "backslash", "whitespace", "none"])
def test_markdown_escape_neutralises_table_and_formatting_characters(raw, escaped):
    """Pipes, backticks, emphasis marks, HTML and line breaks cannot change the structure of the report."""
    assert _md_escape(raw) == escaped


def test_markdown_escape_neutralises_link_brackets():
    """Square brackets from tool output are escaped so they cannot form a Markdown link."""
    assert "[click](" not in _md_escape("[click](http://evil.example)")


def test_markdown_report_labels_the_mode_and_unreachable_services():
    """A simulated report ends with the simulation notice, and a silent URL is labelled 'No HTTP response'."""
    md = render_markdown(rich_run())
    assert "> This run used simulation mode." in md
    assert "### http://10.10.20.5:8080\n\nStatus: -  |  Title: -  |  No HTTP response" in md
    assert "simulation mode" not in render_markdown(rich_run(mode="live"))


def test_markdown_report_states_when_sections_are_empty():
    """An empty run says so in each section instead of rendering empty tables, and only a stage that ran to the
    end says "nothing found": a section whose tool is not in the workflow, whose stage was skipped or failed, or
    whose run failed or is still executing says that instead, so it never reads as a clean result."""
    stages = [StageResult(stage=TOOLS[t].stage, tool=t, status="completed") for t in ("nmap", "whatweb", "nikto")]
    md = render_markdown(make_run(id="empty0000001", tools=["nmap", "whatweb", "nikto"], stages=stages))
    assert "_No open ports found._" in md and "_No web services fingerprinted._" in md
    assert "_No findings recorded._" in md
    web_only = make_run(id="empty0000002", tools=["whatweb", "nikto"],
                        stages=[StageResult(stage="web_fingerprint", tool="whatweb", status="completed"),
                                StageResult(stage="web_vuln_scan", tool="nikto", status="failed",
                                            error="Nikto produced no results for any URL: x")])
    for text in (render_markdown(web_only), render_html(web_only)):
        assert "This workflow has no port scan (Nmap)." in text and "No open ports found." not in text
        assert "Nikto failed: Nikto produced no results for any URL: x" in text
    failed = make_run(id="empty0000003", status="failed", error="nmap failed", tools=["nmap"],
                      stages=[StageResult(stage="port_scan", tool="nmap", status="running")])
    assert "_The run failed before the port scan produced results._" in render_markdown(failed)
    assert "| - | - | - | - | - | not scored |" in render_markdown(failed)  # no "0 open ports" for a failed scan
    # A run still executing: no zero counts next to the ports already found, no "0s" durations, and a notice.
    running = make_run(id="empty0000004", status="running", tools=["nmap", "whatweb"],
                       ports=[PortFinding(host="10.10.20.5", port=22, service="ssh")],
                       stages=[StageResult(stage="port_scan", tool="nmap", status="completed", duration_seconds=2.5),
                               StageResult(stage="web_fingerprint", tool="whatweb", status="running")])
    md = render_markdown(running)
    assert "**Duration:** -  " in md and "| - | - | - | - | - | not scored |" in md
    assert "> **Run in progress.**" in md and "| 2 | web\\_fingerprint | whatweb | running | - |  |" in md
    assert "_Web technologies appear when WhatWeb finishes._" in md and "| 10.10.20.5 | 22 |" in md
    page = render_html(running)
    assert "<b>Run in progress.</b>" in page and "<div class='kpi'><b>-</b><span>Open ports</span></div>" in page
    # A run whose port scan failed skipped the web stages for want of input: their sections say that the run failed
    # before them, not the skipped stages' own "No web services were discovered", which reads as a result.
    scan_failed = make_run(id="empty0000005", status="failed", error="nmap: boom", tools=["nmap", "whatweb", "nikto"],
                           stages=[StageResult(stage="port_scan", tool="nmap", status="failed", error="boom"),
                                   StageResult(stage="web_fingerprint", tool="whatweb", status="skipped",
                                               error="No web services were discovered, nothing to fingerprint."),
                                   StageResult(stage="web_vuln_scan", tool="nikto", status="skipped",
                                               error="No reachable web services, nothing to scan.")])
    md = render_markdown(scan_failed)
    assert "## Open ports\n\n_Nmap failed: boom_" in md
    assert "## Web technologies\n\n_The run failed before WhatWeb produced results._" in md
    assert "## Findings\n\n_The run failed before Nikto produced results._" in md
    page = render_html(scan_failed)
    assert "<h2>Web technologies</h2><p>The run failed before WhatWeb produced results.</p>" in page
    assert "<h2>Findings</h2><p>The run failed before Nikto produced results.</p>" in page
    # After a port scan that completed without finding a web service, the skipped stage's reason is the result.
    no_web = make_run(id="empty0000006", tools=["nmap", "whatweb"],
                      stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                              StageResult(stage="web_fingerprint", tool="whatweb", status="skipped",
                                          error="No web services were discovered, nothing to fingerprint.")])
    assert "_WhatWeb did not run: No web services were discovered, nothing to fingerprint._" in render_markdown(no_web)
    # Each custom-tool call says how it ended, never with an invented exit code, and a call none of whose output was
    # kept says why instead of showing an empty block (the run-limit status already says it on its own).
    calls = custom_calls_run()
    md, page = render_markdown(calls), render_html(calls)
    md = md[md.index("## Custom tool output"):md.index("## Execution log")]
    page = page[page.index("<h2>Custom tool output</h2>"):page.index("<h2>Execution log</h2>")]
    for _fields, status, _where in CALLS:
        assert f"|  {status}  |" in md and f" &middot; {status} &middot; " in page, status
    assert "exit code None" not in md and "```\n\n```" not in md and "<pre></pre>" not in page
    for missing in ("The tool printed nothing.", "Nothing printable was kept: the output was cut at a limit."):
        assert f"\n_{missing}_\n" in md and f"<p>{missing}</p>" in page
    not_kept = md[md.index("### hdr - http://10.10.20.5:8007"):md.index("### hdr - http://10.10.20.5:8008")]
    assert "```" not in not_kept and "\n_" not in not_kept
    # The same calls in a simulated run: one saved before `ended` existed reads as simulated, never with an exit code.
    simulated = calls.model_copy(update={"mode": "simulated"})
    md, page = render_markdown(simulated), render_html(simulated)
    md = md[md.index("## Custom tool output"):md.index("## Execution log")]
    page = page[page.index("<h2>Custom tool output</h2>"):page.index("<h2>Execution log</h2>")]
    for fields, status, _where in CALLS:
        shown = simulated_status(fields, status)
        assert f"|  {shown}  |" in md and f" &middot; {shown} &middot; " in page, shown
    assert "exit code" not in md and "exit code" not in page and md.count("simulated, not started") == 7


# --- Reports: HTML and JSON -----------------------------------------------------------------------

class _Tags(HTMLParser):
    """Collects the tag names of an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)


def test_html_report_escapes_script_tags_and_attribute_breakers():
    """Script tags in a label or finding become text, and a quote in a severity cannot escape its attribute."""
    run = rich_run(label="<script>alert(1)</script>",
                   vulns=[VulnFinding(url="http://10.10.20.5/", severity="low' onmouseover='alert(1)",
                                      description="<script>alert(2)</script>")])
    page = render_html(run)
    parsed = _Tags()
    parsed.feed(page)
    assert "script" not in parsed.tags
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "&lt;script&gt;alert(2)&lt;/script&gt;" in page
    assert "' onmouseover='" not in page and "&#x27; onmouseover=&#x27;" in page


def test_html_report_is_self_contained_and_wraps_long_values():
    """The page carries its own CSS with overflow-wrap for long banners, contains no script, and names the target.
    Only free-text cells (commands and notes, Nmap extra, descriptions, references) may break anywhere: on every
    cell it let a long command squeeze the short columns, so MEDIUM, "completed" and "Duration" broke mid-word
    at 1,440 px. A severity pill never wraps at all."""
    page = render_html(rich_run())
    assert "<script" not in page
    assert "vertical-align:top;overflow-wrap:break-word}" in page and "td.long{overflow-wrap:anywhere}" in page
    assert page.count("overflow-wrap:anywhere") == 1  # in the td.long rule only
    assert page.count("<td class='long'>") == len(rich_run().stages) + len(rich_run().ports) + 2 * len(rich_run().vulns)
    pill = page[page.index(".pill{"):]
    pill = pill[:pill.index("}") + 1]
    assert "white-space:nowrap" in pill and "overflow-wrap:normal" in pill
    assert page.startswith("<!doctype html><html lang='en'>")
    assert "<title>HybridSec report - 127.0.0.1</title>" in page
    assert "Simulation mode." in page and "Simulation mode." not in render_html(rich_run(mode="live"))


@pytest.mark.parametrize("score,colour", [(0, "#16a34a"), (29, "#16a34a"), (30, "#f59e0b"), (69, "#f59e0b"),
                                          (70, "#dc2626"), (100, "#dc2626")])
def test_risk_bar_is_green_below_30_amber_below_70_and_red_from_70(score, colour):
    """The risk bar's width equals the score and its colour follows the 30 and 70 point thresholds."""
    assert _risk_color(score) == colour
    page = render_html(make_run(id="risk0000001", summary=RunSummary(risk_score=score)))
    assert f"width:{score}%;background:{colour}" in page


def test_json_report_is_the_full_run_document():
    """The JSON report is the complete run document, not a summary: every section of the run is present."""
    run = rich_run()
    document = json.loads(render(run, "json"))
    assert document == json.loads(run.model_dump_json())
    assert set(document) >= {"id", "target", "status", "mode", "tools", "stages", "ports", "web", "vulns", "summary",
                             "log", "created_at"}


def test_render_rejects_an_unknown_format_and_knows_four_media_types():
    """Only json, csv, md and html exist, each with its media type; anything else is a ValueError."""
    with pytest.raises(ValueError, match="Unsupported format"):
        render(rich_run(), "pdf")
    assert FORMATS == {"json": "application/json", "csv": "text/csv", "md": "text/markdown", "html": "text/html"}


@pytest.mark.parametrize("target,safe", [("10.10.20.0/24", "10.10.20.0_24"), ("lab.example.edu", "lab.example.edu"),
                                         ("\u4f8b\u3048.jp", "__.jp")])
def test_report_filename_sanitises_the_target_and_carries_the_timestamp(target, safe):
    """The download name replaces unsafe characters in the target and ends with the creation time and format; only
    ASCII letters and digits are kept, because the name goes into a Latin-1 Content-Disposition header."""
    run = make_run(id="fn000000001", target=target, created_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    assert filename(run, "html") == f"hybridsec-{safe}-20260102-030405.html"


# --- API: request validation (422) and checklist refusals (400) ----------------------------------------

OK_RUN = {"target": "127.0.0.1", "authorized": True, "simulate": True}


@pytest.mark.parametrize("body", [
    {**OK_RUN, "target": ""},
    {**OK_RUN, "target": "a" * 256},
    {"target": "127.0.0.1", "simulate": True},
    {**OK_RUN, "authorized": "maybe"},
    {**OK_RUN, "timeout_seconds": -5},
    {**OK_RUN, "timeout_seconds": 5},
    {**OK_RUN, "timeout_seconds": 86401},
    {**OK_RUN, "top_ports": 0},
    {**OK_RUN, "top_ports": 65536},
    {**OK_RUN, "label": "x" * 121},
    {**OK_RUN, "simulate": "sometimes"},
    {**OK_RUN, "tools": "nmap"},
], ids=["empty-target", "oversized-target", "authorized-missing", "authorized-not-bool", "negative-budget",
        "budget-below-10", "budget-above-schema-max", "zero-ports", "too-many-ports", "oversized-label",
        "simulate-not-bool", "tools-not-a-list"])
def test_execute_rejects_malformed_bodies_with_422(client, body):
    """A body that breaks the ExecuteRequest schema is refused by validation before the checklist runs."""
    assert client.post("/api/hybridizations/execute", json=body).status_code == 422


@pytest.mark.parametrize("body", [
    {"tools": [], "objective": PLAN_BODY["objective"]},
    {"tools": ["nmap"] * 7, "objective": PLAN_BODY["objective"]},
    {"tools": ["nmap"], "objective": "too short"},
    {"tools": ["nmap"], "objective": "x" * 2001},
    {"tools": ["nmap"]},
    {**PLAN_BODY, "target_hint": "h" * 256},
], ids=["no-tools", "too-many-tools", "short-objective", "oversized-objective", "no-objective", "oversized-hint"])
def test_plan_rejects_malformed_bodies_with_422(client, body):
    """A plan request needs 1 to 6 tools and an objective of 10 to 2000 characters; anything else is 422. So is a
    body with a lone surrogate escape, whose echoed value FastAPI's own 422 could not encode (it answered 500)."""
    assert client.post("/api/ai/plan", json=body).status_code == 422
    raw = b'{"objective": "Scan the lab host \\ud800 please", "tools": ["nmap"]}'
    resp = client.post("/api/ai/plan", content=raw, headers={"Content-Type": "application/json"})
    assert resp.status_code == 422 and resp.json()["detail"]
    # A 400 whose message quotes the request (here an unknown tool name) is just as encodable.
    raw = b'{"objective": "Scan the lab host please", "tools": ["nmap\\ud800"]}'
    resp = client.post("/api/ai/plan", content=raw, headers={"Content-Type": "application/json"})
    assert resp.status_code == 400 and resp.json()["detail"].startswith("Unknown tool(s): nmap")


def test_execute_refuses_a_blank_target_and_a_budget_above_the_server_maximum(client):
    """A whitespace-only target passes the schema but fails target validation; a budget above the configured
    maximum is refused with the limit in the message."""
    blank = start_run(client, target="   ")
    assert blank.status_code == 400 and "Target is empty" in blank.json()["detail"]
    settings.reload()
    if settings.max_timeout_seconds >= 86400:
        pytest.skip("the configured maximum equals the schema maximum, so no request can exceed it")
    too_long = start_run(client, timeout_seconds=86400)
    assert too_long.status_code == 400
    assert f"may not exceed {settings.max_timeout_seconds}" in too_long.json()["detail"]


def test_execute_refuses_simulation_when_the_server_disables_it(client):
    """With HYBRIDSEC_ALLOW_SIMULATION=false a simulated run is refused and health reports the switch."""
    update_env_file(ENV_FILE, {"HYBRIDSEC_ALLOW_SIMULATION": "false"})
    try:
        resp = start_run(client)
        assert resp.status_code == 400 and "Simulation mode is disabled" in resp.json()["detail"]
        assert client.get("/api/health").json()["simulation_allowed"] is False
    finally:
        update_env_file(ENV_FILE, {"HYBRIDSEC_ALLOW_SIMULATION": ""})
    assert client.get("/api/health").json()["simulation_allowed"] is True


def test_execute_caps_top_ports_at_the_server_maximum(client):
    """Asking for every port is accepted, but the stage runs with the server's maximum."""
    settings.reload()
    run = wait_for_run(client, start_run(client, tools=["nmap"], top_ports=65535).json()["id"])
    assert f"--top-ports {settings.max_top_ports} " in run["stages"][0]["command"]


# --- API: not found, concurrency and list limits ----------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("GET", "/api/runs/doesnotexist"),
    ("DELETE", "/api/runs/doesnotexist"),
    ("GET", "/api/runs/doesnotexist/report?format=csv"),
    ("GET", "/api/ai/plans/doesnotexist"),
    ("POST", "/api/ai/plans/doesnotexist/refine"),
    ("GET", "/api/compare?base=doesnotexist&other=doesnotexist"),
], ids=["run", "delete-run", "report", "plan", "refine", "compare"])
def test_unknown_run_plan_and_report_ids_answer_404(client, method, path):
    """Every endpoint that takes a run or plan id answers 404 with a 'not found' message for an unknown id."""
    resp = client.request(method, path, json={"feedback": "anything useful"} if method == "POST" else None)
    assert resp.status_code == 404 and "not found" in resp.json()["detail"].lower()


def test_execute_with_an_unknown_plan_answers_404(client):
    """Starting a run from a plan id that does not exist is refused with 404, not with a 400 or a crash. A stored run
    or plan that no longer loads answers 422 with an explanation instead of a bare 500, and does not break the lists."""
    resp = start_run(client, plan_id="doesnotexist")
    assert resp.status_code == 404 and resp.json()["detail"] == "Plan not found."
    # So is a plan id that SQLite cannot be given (a lone surrogate, which JSON allows as \ud800), on the current
    # path and on the legacy alias: no stored plan can have it.
    raw = b'{"target": "127.0.0.1", "authorized": true, "simulate": true, "plan_id": "\\ud800"}'
    for path in ("/api/hybridizations/execute", "/hybridizations/execute"):
        resp = client.post(path, content=raw, headers={"Content-Type": "application/json"})
        assert resp.status_code == 404 and resp.json()["detail"] == "Plan not found.", path
    with storage.connect() as conn:
        conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) VALUES (?, ?, ?, ?, ?)",
                     ("damagedrun01", "2001-01-01T00:00:00+00:00", "10.10.20.5", "completed",
                      json.dumps({"id": "damagedrun01", "target": "10.10.20.5", "status": "cancelled",
                                  "created_at": "2001-01-01T00:00:00+00:00"})))
        conn.execute("INSERT OR REPLACE INTO plans (id, created_at, document) VALUES (?, ?, ?)",
                     ("damagedplan1", "2001-01-01T00:00:00+00:00", '{"id": "damagedplan1"'))
    try:
        for path in ("/api/runs/damagedrun01", "/api/runs/damagedrun01/report?format=md",
                     "/api/compare?base=damagedrun01&other=damagedrun01", "/api/ai/plans/damagedplan1"):
            resp = client.get(path)
            assert resp.status_code == 422 and "cannot be read" in resp.json()["detail"], path
        assert start_run(client, plan_id="damagedplan1").status_code == 422
        assert client.get("/api/ai/plans").status_code == 200
        assert client.delete("/api/runs/damagedrun01").status_code == 204
    finally:
        storage.delete_run("damagedrun01")
        with storage.connect() as conn:
            conn.execute("DELETE FROM plans WHERE id = 'damagedplan1'")


def test_compare_requires_both_runs_to_exist(client, finished_run):
    """One known and one unknown run id is a 404 that names the problem."""
    resp = client.get("/api/compare", params={"base": finished_run["id"], "other": "doesnotexist"})
    assert resp.status_code == 404 and resp.json()["detail"] == "One or both runs were not found."


def test_compare_of_a_run_with_itself_reports_no_changes_through_the_api(client, finished_run):
    """The comparison endpoint applied to the same run twice reports empty lists and a zero risk delta."""
    diff = client.get("/api/compare", params={"base": finished_run["id"], "other": finished_run["id"]}).json()
    assert diff["risk_delta"] == 0
    assert all(diff[key] == [] for key in ("ports_added", "ports_removed", "ports_changed", "tech_added",
                                            "tech_removed", "vulns_added", "vulns_removed"))


def test_two_simulated_runs_on_the_same_target_compare_equal(client, finished_run):
    """Simulation is deterministic end to end: a second run on the same target shows no differences."""
    second = wait_for_run(client, start_run(client, tools=["nmap", "whatweb", "nikto"]).json()["id"])
    assert second["ports"] == finished_run["ports"] and second["vulns"] == finished_run["vulns"]
    diff = client.get("/api/compare", params={"base": finished_run["id"], "other": second["id"]}).json()
    assert diff["risk_delta"] == 0 and diff["ports_added"] == [] and diff["vulns_added"] == []
    assert diff["tech_added"] == [] and diff["tech_removed"] == []


def test_run_at_the_concurrency_cap_shows_live_progress_and_blocks_new_runs(client, monkeypatch):
    """While one run holds the single slot, GET shows it in progress, a second run gets 429 and deleting it 409."""
    release = threading.Event()
    real_handler = hybrid.STAGE_HANDLERS["port_scan"]

    def gated(*args):
        release.wait(5)
        return real_handler(*args)

    monkeypatch.setitem(hybrid.STAGE_HANDLERS, "port_scan", gated)
    update_env_file(ENV_FILE, {"HYBRIDSEC_MAX_CONCURRENT_RUNS": "1"})
    try:
        first = start_run(client, tools=["nmap"])
        assert first.status_code == 202, first.text
        run_id = first.json()["id"]
        live = client.get(f"/api/runs/{run_id}").json()
        assert live["status"] in {"queued", "running"} and live["finished_at"] is None
        second = start_run(client)
        assert second.status_code == 429 and "already executing" in second.json()["detail"]
        assert client.delete(f"/api/runs/{run_id}").status_code == 409
    finally:
        release.set()
        update_env_file(ENV_FILE, {"HYBRIDSEC_MAX_CONCURRENT_RUNS": ""})
    run = wait_for_run(client, run_id)
    assert run["status"] == "completed" and run["stages"][0]["status"] == "simulated"


def test_run_and_plan_list_limits_are_clamped_to_at_least_one(client, finished_run):
    """limit=0 or a negative limit still returns one item, and a non-numeric limit is a 422."""
    assert len(client.get("/api/runs", params={"limit": 0}).json()) == 1
    assert len(client.get("/api/runs", params={"limit": 1}).json()) == 1
    assert client.get("/api/runs", params={"limit": "many"}).status_code == 422
    assert client.post("/api/ai/plan", json=PLAN_BODY).status_code == 200
    assert len(client.get("/api/ai/plans", params={"limit": -3}).json()) == 1


# --- API: reports and legacy aliases --------------------------------------------------------------

@pytest.mark.parametrize("fmt,media_type", [("json", "application/json"), ("csv", "text/csv"),
                                            ("md", "text/markdown"), ("html", "text/html")])
def test_each_report_format_has_its_media_type_and_download_name(client, finished_run, fmt, media_type):
    """Every format downloads as an attachment with its own media type and a hybridsec-<target>-<time> name."""
    resp = client.get(f"/api/runs/{finished_run['id']}/report", params={"format": fmt})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == f"{media_type}; charset=utf-8"
    disposition = resp.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="hybridsec-127.0.0.1-') and disposition.endswith(f'.{fmt}"')


def test_report_format_is_case_insensitive_and_inline_when_download_is_false(client, finished_run):
    """format=CSV works like csv, and download=false shows the report in the browser instead of saving it."""
    inline = client.get(f"/api/runs/{finished_run['id']}/report", params={"format": "CSV", "download": "false"})
    assert inline.status_code == 200 and inline.headers["content-type"].startswith("text/csv")
    assert "content-disposition" not in inline.headers


def test_unknown_report_format_answers_400(client, finished_run):
    """A format outside json, csv, md and html is refused with the list of valid formats."""
    resp = client.get(f"/api/runs/{finished_run['id']}/report", params={"format": "pdf"})
    assert resp.status_code == 400 and "format must be one of json, csv, md, html" in resp.json()["detail"]


def test_json_report_equals_the_run_the_api_serves(client, finished_run):
    """The downloadable JSON report is exactly the run document returned by GET /api/runs/{id}."""
    report = client.get(f"/api/runs/{finished_run['id']}/report", params={"format": "json"}).json()
    assert report == client.get(f"/api/runs/{finished_run['id']}").json()


def test_legacy_execute_alias_queues_a_run_like_the_new_path(client):
    """The original project's POST /hybridizations/execute still queues a run (202) that completes."""
    resp = client.post("/hybridizations/execute", json={**OK_RUN, "tools": ["nmap"]})
    assert resp.status_code == 202, resp.text
    run = wait_for_run(client, resp.json()["id"])
    assert run["status"] == "completed" and run["tools"] == ["nmap"]


# --- API: system endpoints and settings -----------------------------------------------------------

def test_tools_catalogue_has_the_full_shape_and_consistent_install_flags(client):
    """Each tool entry has every ToolInfo field, its registry stage, and installed/path/version that agree."""
    tools = client.get("/api/tools").json()
    assert [t["name"] for t in tools] == list(TOOLS)
    for entry in tools:
        assert set(entry) == {"name", "display_name", "category", "description", "stage", "installed", "path",
                              "version", "install_hint", "profiles"}
        assert entry["stage"] == TOOLS[entry["name"]].stage and entry["install_hint"]
        assert [p["key"] for p in entry["profiles"]] == [p.key for p in TOOLS[entry["name"]].profiles]
        assert [p["default"] for p in entry["profiles"]] == [True] + [False] * (len(entry["profiles"]) - 1)
        assert entry["installed"] == (entry["path"] is not None)
        if not entry["installed"]:
            assert entry["version"] is None
    # row names a URL path must encode (a line break too, which Starlette's {name:path} would not match)
    odd = ["a/b", "c%2Fd", "e?f", "g#h", "50%", " sp ", "/x", "\u00e9t\u00e9", "n\nl"]
    # Custom tools have endpoints of their own and never appear in /api/tools or the health. A cross-site page cannot
    # register or delete one: the middleware refuses it before validation.
    try:
        created = client.post("/api/tools/custom", json=CUSTOM_BODY)
        assert created.status_code == 201, created.text
        info = created.json()
        assert set(info) == {"name", "description", "program", "args", "scope", "timeout_seconds", "created_at",
                             "installed", "path", "install_hint", "refused", "blocked"}
        assert info["installed"] is False and info["path"] is None and info["refused"] is info["blocked"] is False
        assert "Simulation mode works without it" in info["install_hint"]
        assert [t["name"] for t in client.get("/api/tools").json()] == list(TOOLS)
        assert set(client.get("/api/health").json()["tools"]) == set(TOOLS)
        listing = client.get("/api/tools/custom").json()
        assert set(listing) == {"allowed_programs", "tools", "unreadable"} and listing["unreadable"] == []
        assert listing["allowed_programs"] == ["curl", "hybridsec-test-missing-program", "sslscan", "whois"]
        assert [t["name"] for t in listing["tools"]] == ["pytestcheck"]
        # The allow-list is listed as written (the settings only lower-case it: no sqlite3 -> sqlite, no full path ->
        # curl), without the entries that are always refused, and the "not on the list" refusal names the same.
        try:
            with pytest.MonkeyPatch.context() as mp:
                mp.setenv("HYBRIDSEC_CUSTOM_PROGRAMS", "bash,/usr/bin/curl,Curl.exe,nmap,sslscan,sqlite3,whois2,pwsh")
                shown = client.get("/api/tools/custom").json()["allowed_programs"]
                dig = client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name="pytestdig", program="dig"))
        finally:
            settings.reload()
        assert shown == ["/usr/bin/curl", "Curl.exe", "sslscan", "whois2"]  # as written in .env
        assert dig.status_code == 400 and "(/usr/bin/curl, Curl.exe, sslscan, whois2)" in dig.json()["detail"]
        # A program found on this machine whose file may not run (a script, a share, HybridSec's own folder) is
        # blocked: not installed, but not missing either (the dashboard says "refused"), and install_hint says why.
        problem = "Program: hybridsec-test-missing-program resolves to C:\\Tools\\scan.bat, which is a script file."
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(custom, "find_program", lambda program: (None, problem))
            blocked = client.get("/api/tools/custom").json()["tools"][0]
        assert (blocked["installed"], blocked["path"], blocked["refused"]) == (False, None, False)
        assert blocked["blocked"] is True and blocked["install_hint"] == problem
        assert client.post("/api/tools/custom", json=CUSTOM_BODY).status_code == 409
        slow = client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name="pytestslow",
                                                          timeout_seconds=settings.max_timeout_seconds + 1))
        assert slow.status_code == 400 and "may not exceed" in slow.json()["detail"]
        shell = client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name="pytestshell", program="bash"))
        assert shell.status_code == 400 and "shell, interpreter or launcher" in shell.json()["detail"]
        evil = {"Origin": "http://evil.example"}
        assert client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name="pytestx"), headers=evil).status_code == 403
        assert client.delete("/api/tools/custom/pytestcheck", headers=evil).status_code == 403
        allowed = custom.allowed_programs(settings.custom_programs)
        for i in range(9):  # pytestcheck plus 9 more reach MAX_CUSTOM_TOOLS
            filler = custom.validate_definition(CustomToolCreate(**dict(CUSTOM_BODY, name=f"pytestfull{i}")), allowed,
                                                datetime.now(timezone.utc), look_up=False)
            assert storage.add_custom_tool(filler, custom.MAX_CUSTOM_TOOLS) == "added"
        full = client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name="pytestextra"))
        assert full.status_code == 400 and full.json()["detail"] == \
            "At most 10 custom tools can be registered. Delete one first."
        assert client.delete("/api/tools/custom/nmap").status_code == 400
        assert client.delete("/api/tools/custom/pytestcheck").status_code == 204
        missing = client.delete("/api/tools/custom/pytestcheck")
        assert missing.status_code == 404 and missing.json()["detail"] == "Custom tool not found."
        # A stored row whose definition no longer loads, or holds a tool of another name, is listed by its row name
        # as unreadable: it still counts towards the limit, and DELETE by that name (as written) removes it.
        with storage.connect() as conn:
            conn.execute("INSERT INTO custom_tools (name, created_at, document) VALUES (?, ?, ?)",
                         ("PyTestBroken", "2001-01-01T00:00:00+00:00", '{"name": "pytestbroken"'))
            conn.execute("UPDATE custom_tools SET document = ? WHERE name = 'pytestfull0'",
                         (filler.model_copy(update={"name": "pytestrenamed"}).model_dump_json(),))
        listing = client.get("/api/tools/custom").json()
        assert listing["unreadable"] == ["PyTestBroken", "pytestfull0"]
        assert [t["name"] for t in listing["tools"]] == [f"pytestfull{i}" for i in range(1, 9)]
        full = client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name="pytestextra"))
        assert full.status_code == 400 and full.json()["detail"].startswith("At most 10 custom tools")
        for name in listing["unreadable"]:
            assert client.delete(f"/api/tools/custom/{name}").status_code == 204, name
        assert client.get("/api/tools/custom").json()["unreadable"] == []
        # A row no request can name (NULL, a blob, . or ..) is neither listed nor counted, so it never holds a place
        # nothing could free: with 8 tools and four such rows, a ninth and a tenth register and an eleventh does not.
        with storage.connect() as conn:
            for value in (None, b"\x00\xff", ".", ".."):
                conn.execute("INSERT INTO custom_tools (name, created_at, document) VALUES (?, ?, ?)",
                             (value, "2001-01-01T00:00:00+00:00", "{"))
        listing = client.get("/api/tools/custom").json()
        assert listing["unreadable"] == [] and len(listing["tools"]) == 8
        assert [client.post("/api/tools/custom", json=dict(CUSTOM_BODY, name=name)).status_code
                for name in ("pytestextra", "pytestcheck", "pytestmore")] == [201, 201, 400]
        # Any other row name, also one with / ? # or %, is listed and deleted by that name, percent-encoded in the
        # path as the dashboard sends it.
        with storage.connect() as conn:
            for name in odd:
                conn.execute("INSERT INTO custom_tools (name, created_at, document) VALUES (?, ?, ?)",
                             (name, "2001-01-01T00:00:00+00:00", "{"))
        assert client.get("/api/tools/custom").json()["unreadable"] == sorted(odd)
        for name in odd:
            assert client.delete("/api/tools/custom/" + urllib.parse.quote(name, safe="")).status_code == 204, name
        assert client.get("/api/tools/custom").json()["unreadable"] == []
    finally:
        for name in ("pytestcheck", "pytestextra", "pytestmore", "pytestdig", "PyTestBroken",
                     *(f"pytestfull{i}" for i in range(9)), *odd):
            storage.delete_custom_tool(name)
        with storage.connect() as conn:
            conn.execute("DELETE FROM custom_tools WHERE typeof(name) != 'text' OR name IN ('.', '..')")


def test_health_reports_tools_and_limits_consistent_with_the_settings(client):
    """Health lists every tool as installed yes/no and the four limits with the values the settings hold."""
    health = client.get("/api/health").json()
    settings.reload()
    assert set(health) == {"status", "app", "version", "ai_provider", "ai_model", "simulation_allowed",
                           "allowed_targets", "tools", "limits", "runs"}
    # The run totals the Overview shows come from the whole history, not from the capped run list.
    counts = storage.count_runs()
    assert health["runs"]["total"] == sum(counts.values()) and health["runs"]["completed"] == counts.get("completed", 0)
    assert client.get("/api/runs", params={"limit": 1}).headers["X-Total-Count"] == str(sum(counts.values()))
    assert health["status"] == "ok" and health["app"] == settings.app_name and health["version"] == settings.version
    assert set(health["tools"]) == set(TOOLS) and all(isinstance(v, bool) for v in health["tools"].values())
    assert health["limits"] == {"max_timeout_seconds": settings.max_timeout_seconds,
                                "default_timeout_seconds": settings.default_timeout_seconds,
                                "max_top_ports": settings.max_top_ports,
                                "max_concurrent_runs": settings.max_concurrent_runs}
    assert health["ai_provider"] == "rules" and health["ai_model"] is None


def test_health_stays_reachable_under_a_foreign_host_header(client):
    """Uptime checks may use any host name for /api/health, while other endpoints keep the Host guard."""
    assert client.get("/api/health", headers={"Host": "monitor.example"}).status_code == 200
    assert client.get("/api/tools", headers={"Host": "monitor.example"}).status_code == 400


def test_settings_never_return_key_values_only_presence_flags(client):
    """After saving keys, no response ever contains them: the view has only *_key_configured flags."""
    fake_anthropic, fake_openai = "test-anthropic-key-not-real-000001", "test-openai-key-not-real-000001"
    try:
        saved = client.put("/api/settings", json={"anthropic_api_key": fake_anthropic, "openai_api_key": fake_openai})
        assert saved.status_code == 200, saved.text
        for resp in (saved, client.get("/api/settings"), client.get("/api/health")):
            assert fake_anthropic not in resp.text and fake_openai not in resp.text
        view = client.get("/api/settings").json()
        assert view["anthropic_key_configured"] is True and view["openai_key_configured"] is True
        assert (view["anthropic_key_source"], view["openai_key_source"]) == ("env_file", "env_file")
        assert not [name for name in SettingsView.model_fields if name.endswith("_api_key")]
    finally:
        client.put("/api/settings", json={"anthropic_api_key": "", "openai_api_key": ""})
    view = client.get("/api/settings").json()
    assert view["anthropic_key_configured"] is False and view["openai_key_configured"] is False
    assert view["anthropic_key_source"] is None and view["openai_key_source"] is None
    # Clearing cannot remove a key the server's own environment sets (a blank KEY= never masks it): the view says
    # where the key comes from, so the dashboard can tell the operator instead of claiming it was cleared.
    os.environ["OPENAI_API_KEY"] = fake_openai
    try:
        view = client.put("/api/settings", json={"openai_api_key": ""}).json()
        assert view["openai_key_configured"] is True and view["openai_key_source"] == "environment"
        # The dashboard warns from this. Only the two keys matter here: whether the provider is listed too depends
        # on whether an earlier test saved it to the shared test .env file (the suite's environment sets it).
        assert view["environment_settings"]["openai_api_key"] == "OPENAI_API_KEY"
        assert "anthropic_api_key" not in view["environment_settings"]
        assert fake_openai not in json.dumps(view)
    finally:
        del os.environ["OPENAI_API_KEY"]


@pytest.mark.parametrize("body", [
    {"max_timeout_seconds": 5}, {"max_timeout_seconds": 86401}, {"default_timeout_seconds": 0},
    {"max_top_ports": 0}, {"max_top_ports": 65536}, {"max_concurrent_runs": 0}, {"max_concurrent_runs": 21},
    {"ai_provider": "gemini"}, {"allowed_targets": "10.10.20.5"}, {"anthropic_api_key": "k" * 513},
    {"anthropic_model": "m" * 101}, {"openai_base_url": "u" * 301}, {"allow_simulation": "sometimes"},
], ids=["timeout-low", "timeout-high", "default-zero", "ports-zero", "ports-high", "runs-zero", "runs-high",
        "unknown-provider", "targets-not-a-list", "key-too-long", "model-too-long", "url-too-long", "flag-not-bool"])
def test_settings_update_rejects_out_of_range_values_with_422(client, body):
    """Each SettingsUpdate field has a range or type; a value outside it is refused before anything is written."""
    assert client.put("/api/settings", json=body).status_code == 422


def test_settings_update_rejects_an_empty_body_and_a_short_key_with_400(client):
    """Sending nothing to change, or a key too short to be real, is a 400 with an explanation."""
    empty = client.put("/api/settings", json={})
    assert empty.status_code == 400 and "Nothing to update" in empty.json()["detail"]
    short = client.put("/api/settings", json={"openai_api_key": "short"})
    assert short.status_code == 400 and "looks malformed" in short.json()["detail"]


def test_test_planner_reports_timing_and_no_fallback_with_the_rules_engine(client):
    """The Test planner button gets a complete result: no note, no model, a bounded summary and the elapsed time."""
    result = client.post("/api/settings/test-planner").json()
    assert result["ok"] is True and result["provider"] == "rules"
    assert result["model"] is None and result["note"] is None
    assert isinstance(result["elapsed_seconds"], float) and result["elapsed_seconds"] >= 0
    assert 0 < len(result["summary"]) <= 400
    assert result["steps"] == ["1. nmap (port_scan)", "2. whatweb (web_fingerprint)"]
    # The API documents both uses of the note: why the planner fell back, or a note about the provider's plan.
    described = PlannerTestResult.model_fields["note"].description
    assert "Why the planner fell back to the rules engine" in described
    assert "a tool the model added that was removed from the workflow" in described


# --- Request guards, caching and the dashboard ----------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("localhost:8000", "localhost"),
    ("[::1]:8000", "::1"),
    ("http://Example.COM:80/x", "example.com"),
    ("::1", "::1"),
    ("[::1", "[::1"),
    ("", ""),
    ("  LocalHost ", "localhost"),
], ids=["port", "ipv6-port", "url", "bare-ipv6", "unbalanced", "empty", "case"])
def test_hostname_helper_strips_ports_brackets_and_schemes(raw, expected):
    """The guard compares bare lower-case host names: ports, IPv6 brackets and URL schemes are removed."""
    assert _hostname(raw) == expected


@pytest.mark.parametrize("host", ["[::1]:8000", "127.0.0.1:8000", "LOCALHOST"])
def test_loopback_host_headers_with_ports_or_brackets_are_accepted(client, host):
    """The server's own names pass the Host guard in any spelling a browser may use."""
    assert client.get("/api/tools", headers={"Host": host}).status_code == 200


def test_read_requests_are_not_subject_to_the_cross_site_check(client):
    """The cross-site guard protects state changes only; a GET with a foreign Origin still answers."""
    headers = {"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}
    assert client.get("/api/tools", headers=headers).status_code == 200


def test_null_origin_passes_unless_the_browser_marks_the_request_cross_site(client):
    """Origin: null carries no host to compare, so only the Sec-Fetch-Site header decides."""
    assert client.post("/api/ai/plan", json=PLAN_BODY, headers={"Origin": "null"}).status_code == 200
    rejected = client.post("/api/ai/plan", json=PLAN_BODY, headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"})
    assert rejected.status_code == 403


@pytest.mark.parametrize("site", ["same-origin", "same-site", "none"])
def test_sec_fetch_site_values_other_than_cross_site_pass(client, site):
    """Only Sec-Fetch-Site: cross-site is rejected; same-origin, same-site and typed-in (none) requests pass."""
    assert client.post("/api/ai/plan", json=PLAN_BODY, headers={"Sec-Fetch-Site": site}).status_code == 200


def test_origin_comparison_ignores_scheme_and_letter_case(client):
    """An Origin that differs from the Host only in scheme spelling or letter case is the same origin."""
    headers = {"Host": "localhost:8000", "Origin": "HTTP://LocalHost:8000"}
    assert client.post("/api/ai/plan", json=PLAN_BODY, headers=headers).status_code == 200


@pytest.mark.parametrize("method,path", [("PUT", "/api/settings"), ("DELETE", "/api/runs/doesnotexist"),
                                         ("POST", "/hybridizations/execute")])
def test_every_state_changing_method_is_guarded_against_cross_site_origins(client, method, path):
    """PUT, DELETE and the legacy POST path are all rejected with 403 when they come from another site."""
    resp = client.request(method, path, json={"ai_provider": "rules"}, headers={"Origin": "http://evil.example"})
    assert resp.status_code == 403 and "Use the dashboard served by this server" in resp.json()["detail"]


def test_dashboard_and_static_files_are_served_with_no_cache(client):
    """The page and its static files must be re-validated on every load; API answers carry no such header."""
    for path in ("/", "/static/app.js", "/static/styles.css"):
        resp = client.get(path)
        assert resp.status_code == 200 and resp.headers["cache-control"] == "no-cache", path
    assert "cache-control" not in client.get("/api/tools").headers
    assert client.get("/static/does-not-exist.js").status_code == 404


def test_favicon_is_an_inline_svg_with_long_caching(client):
    """The favicon is served from code as SVG, so no image file is needed, and browsers may cache it for a day."""
    resp = client.get("/favicon.ico")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("image/svg+xml")
    assert resp.text.startswith("<svg") and resp.headers["cache-control"] == "public, max-age=86400"


class _Assets(HTMLParser):
    """Collects every src and href attribute of an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.refs: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.refs += [value for name, value in attrs if name in {"src", "href"} and value]


def test_dashboard_references_only_static_assets_that_exist(client):
    """Every /static/ file the dashboard page loads exists on disk and is served; other links are anchors,
    data URIs or https documentation links."""
    parser = _Assets()
    parser.feed(client.get("/").text)
    local = [ref for ref in parser.refs if ref.startswith("/static/")]
    assert local, "the dashboard should load its script and stylesheet from /static/"
    for ref in local:
        assert (settings.dashboard_dir / ref.removeprefix("/static/")).is_file(), ref
        assert client.get(ref).status_code == 200, ref
    others = [ref for ref in parser.refs if not ref.startswith("/static/")]
    assert all(ref.startswith(("#", "data:", "https://")) for ref in others), others
