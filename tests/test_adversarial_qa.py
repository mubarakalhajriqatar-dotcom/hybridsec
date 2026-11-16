"""Regression tests from the adversarial QA review round (round four of six) before the committee demo.

Each test names the defect it protects against. Like the rest of the suite they run offline: scanners are
replaced with fakes, the planner never calls a provider, and the environment is the private .env and data
directory that tests/test_api.py sets up at import.
"""
from __future__ import annotations

import csv
import io
import json
import re
import socket
import threading
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import tests.test_api as T  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import envfile, hybrid, storage
from app.compare import compare_runs
from app.config import ENV_FILE, settings
from app.envfile import update_env_file
from app.main import app
from app.reports import render_csv, render_html, render_markdown
from app.routers.settings_api import require_local
from app.schemas import CustomTool, CustomToolOutput, PortFinding, StageResult, VulnFinding, WebFinding
from app.tools import parsers, registry
from app.tools.runner import CommandResult
from tests.test_api import make_run, run_stage_handler, start_run, wait_for_run


@pytest.fixture(scope="module")
def client():
    # The TestClient's peer is "testclient", not a loopback IP, so the settings guard is overridden here.
    app.dependency_overrides[require_local] = lambda: None
    with TestClient(app, base_url="http://localhost:8000") as c:
        yield c
    app.dependency_overrides.clear()


NMAP_HEAD = '<?xml version="1.0"?><nmaprun scanner="nmap">'
ONE_HOST = (NMAP_HEAD + '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
            '<port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port>'
            '</ports></host>')


def fake_tools(monkeypatch, run_command) -> None:
    """Pretend every scanner is installed and route run_command to the given fake (nothing is executed, and name
    lookups answer IPv4 only so no host name reaches the real resolver)."""
    monkeypatch.setattr(hybrid, "resolve_binary", lambda spec: f"/fake/bin/{spec.name}")
    monkeypatch.setattr(hybrid, "run_command", run_command)
    monkeypatch.setattr(hybrid, "_address_families", lambda hostname: {socket.AF_INET})


def report_path(command: list[str]) -> str | None:
    """The report file a fake WhatWeb/Nikto call must write, taken from the command line."""
    for index, part in enumerate(command):
        if part.startswith("--log-json="):
            return part.split("=", 1)[1]
        if part == "-output":
            return command[index + 1]
    return None


# --- Request validation ---------------------------------------------------------------------------

def test_blank_label_is_stored_as_no_label(client):
    """A whitespace-only label used to be stored verbatim and showed up as an empty run title in the history."""
    run = wait_for_run(client, start_run(client, label="   ").json()["id"])
    assert run["label"] is None
    assert next(r for r in client.get("/api/runs").json() if r["id"] == run["id"])["label"] is None


def test_blank_objective_and_feedback_are_refused(client):
    """The schema's minimum lengths count spaces; blank text must not reach the planner or create a revision."""
    blank = client.post("/api/ai/plan", json={"tools": ["nmap"], "objective": " " * 12})
    assert blank.status_code == 400 and "not only spaces" in blank.json()["detail"]
    plan = client.post("/api/ai/plan", json={"tools": ["nmap"], "objective": "Plan a port scan of a lab host."}).json()
    blank = client.post(f"/api/ai/plans/{plan['id']}/refine", json={"feedback": "    "})
    assert blank.status_code == 400 and "not only spaces" in blank.json()["detail"]
    padded = client.post(f"/api/ai/plans/{plan['id']}/refine", json={"feedback": "  shorter  "})
    assert padded.status_code == 200 and padded.json()["feedback"] == "shorter"
    # A plan id holding a lone surrogate (JSON allows \ud800, SQLite cannot store it) is an unknown plan: 404 on the
    # current and the legacy execute route, not a 500 (issue 3 of the 12 November test round).
    body = json.dumps({"target": "127.0.0.1", "authorized": True, "simulate": True, "plan_id": "\ud800"})
    assert "\\ud800" in body  # sent as the JSON escape, as a client would send it
    for path in ("/api/hybridizations/execute", "/hybridizations/execute"):
        answer = client.post(path, content=body, headers={"Content-Type": "application/json"})
        assert answer.status_code == 404 and answer.json()["detail"] == "Plan not found.", path


def test_tool_names_with_surrounding_spaces_are_accepted(client):
    """known_tool() and order_tools() must agree: " NMAP " is nmap for both."""
    assert registry.unknown_tools([" NMAP ", "whatweb "]) == []
    assert registry.order_tools([" NMAP "]) == ["nmap"]
    run = wait_for_run(client, start_run(client, tools=[" NMAP "]).json()["id"])
    assert run["tools"] == ["nmap"]


# --- Parser tolerance -----------------------------------------------------------------------------

def test_whatweb_parser_tolerates_unexpected_shapes():
    """Odd JSON shapes (lists instead of dicts, scalars instead of lists, junk status) never crash the stage."""
    probe = lambda text: parsers.parse_whatweb_json(text, "http://10.0.0.5", "10.0.0.5", 80)  # noqa: E731
    assert probe(json.dumps([{"target": "http://10.0.0.5", "http_status": 200, "plugins": [1, 2]}])).reachable
    assert probe(json.dumps([{"plugins": {"X": ["a"]}}])).technologies == [{"name": "X"}]  # detail dropped, name kept
    assert probe(json.dumps([{"plugins": {"PHP": {"version": "7.4"}}}])).technologies == [{"name": "PHP", "version": "7.4"}]
    assert probe(json.dumps([{"http_status": "200", "plugins": {}}])).status_code == 200
    assert probe(json.dumps([{"http_status": "abc", "plugins": {}}])).status_code is None
    assert probe(json.dumps([{"target": None, "plugins": {"X": None, "Y": {"string": None, "version": None}}}])).final_url is None
    assert probe(json.dumps([{"plugins": {"Title": {"string": [123]}}}])).title == "123"


def test_nikto_parser_tolerates_unexpected_shapes_and_builds_valid_urls():
    """Damaged entries are skipped, Nikto's url field always yields a well-formed URL, and the concatenated
    objects / trailing comma that Nikto's JSON writer is known to emit are still read as JSON."""
    base = "http://10.0.0.5"
    assert parsers.parse_nikto_json(json.dumps([{"vulnerabilities": [1, "x", None, {"msg": None}]}]), base) == []
    assert parsers.parse_nikto_json(json.dumps([{"vulnerabilities": {"msg": "x"}}]), base) == []
    urls = [v.url for v in parsers.parse_nikto_json(json.dumps([{"vulnerabilities": [
        {"msg": "A", "url": "/manager/html"}, {"msg": "B", "url": "foo["}, {"msg": "C", "url": 5},
        {"msg": "D", "url": "http://other/x"}, {"msg": "E", "url": ""}, {"msg": "F"}]}]), base)]
    assert urls == ["http://10.0.0.5/manager/html", "http://10.0.0.5/foo[", "http://10.0.0.5/5", "http://other/x",
                    base, base]
    concatenated = '{"host":"h","vulnerabilities":[{"msg":"A","url":"/"}]},{"host":"h","vulnerabilities":[{"msg":"B","url":"/b"}]}'
    assert parsers.nikto_output_is_json(concatenated)
    assert [v.description for v in parsers.parse_nikto_json(concatenated, base)] == ["A", "B"]
    assert parsers.nikto_output_is_json('{"host":"h","vulnerabilities":[{"msg":"A"}]},')
    assert not parsers.nikto_output_is_json("+ Server: nginx\n+ 1 host(s) tested")


def test_compare_survives_a_malformed_finding_url(client):
    """urlsplit() raises on "http://hfoo[" (unbalanced bracket); the comparison must not answer 500."""
    now = datetime.now(timezone.utc)
    bad = make_run(id="qacmp0000001", target="h", tools=["nikto"], created_at=now,
                   vulns=[VulnFinding(url="http://hfoo[", severity="low", description="x"),
                          VulnFinding(url="", severity="low", description="y")])
    good = make_run(id="qacmp0000002", target="h", tools=["nikto"], created_at=now)
    assert len(compare_runs(bad, good).vulns_removed) == 2
    storage.save_run(bad)
    storage.save_run(good)
    # A stored document that is JSON but not an object used to make GET /api/runs answer 500, so one damaged row
    # took the whole Runs page down (issue 10 of the 12 November test round): it is listed as unreadable instead,
    # and opening or comparing it says it cannot be read.
    shapes = {"qacmp0000003": "null", "qacmp0000004": "[]", "qacmp0000005": "7", "qacmp0000006": '"run"'}
    with storage.connect() as conn:
        for run_id, document in shapes.items():
            conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) "
                         "VALUES (?, ?, ?, ?, ?)", (run_id, "2099-01-01T12:00:00+00:00", "h", "completed", document))
    try:
        assert client.get("/api/compare", params={"base": bad.id, "other": good.id}).status_code == 200
        listing = client.get("/api/runs")
        assert listing.status_code == 200
        listed = {r["id"]: r["status"] for r in listing.json() if r["id"] in shapes}
        assert listed == dict.fromkeys(shapes, "unreadable")
        assert client.get("/api/runs/qacmp0000004").status_code == 422
        compared = client.get("/api/compare", params={"base": good.id, "other": "qacmp0000003"})
        assert compared.status_code == 422 and "cannot be read" in compared.json()["detail"]
    finally:
        storage.delete_run(bad.id)
        storage.delete_run(good.id)
        for run_id in shapes:
            storage.delete_run(run_id)


# --- Pipeline robustness --------------------------------------------------------------------------

def test_nmap_stopped_before_any_host_fails_instead_of_reporting_no_ports(monkeypatch):
    """Killed at the time limit with nothing salvaged, Nmap has produced no evidence: the stage must fail with
    advice, not complete as "no open ports" (a false negative). With one complete host salvaged, the stage
    still completes with the partial-results note."""
    cut_before_any_host = NMAP_HEAD + '<host><status state="up"/><addr'
    fake_tools(monkeypatch, lambda command, timeout: CommandResult(
        command=command, exit_code=None, stdout=cut_before_any_host, stderr="", duration_seconds=30, timed_out=True))
    run = make_run(id="qanmap000001", target="10.0.0.0/24", status="running", stages=[StageResult(stage="port_scan", tool="nmap")])
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "failed" and "before it reported any host" in stage.error and "time budget" in stage.error
    assert hybrid._final_outcome(run.stages)[0] == "failed"

    cut_after_one_host = ONE_HOST + '<host><status state="up"/><address addr="10.0.0.6" addrty'
    fake_tools(monkeypatch, lambda command, timeout: CommandResult(
        command=command, exit_code=None, stdout=cut_after_one_host, stderr="", duration_seconds=30, timed_out=True))
    run = make_run(id="qanmap000002", target="10.0.0.0/24", status="running", stages=[StageResult(stage="port_scan", tool="nmap")])
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "completed" and len(run.ports) == 2
    assert "truncated" in stage.error and "down" not in stage.error


def test_vanished_binary_is_reported_readably_and_keeps_partial_findings(monkeypatch):
    """run_command raising OSError (binary deleted between resolve and start) used to crash the whole stage
    with a raw exception text; in the web stages that threw away the URLs already probed."""
    def missing(command, timeout):
        raise FileNotFoundError(2, "No such file or directory", command[0])
    fake_tools(monkeypatch, missing)
    run = make_run(id="qaos00000001", target="10.0.0.5", status="running", stages=[StageResult(stage="port_scan", tool="nmap")])
    stage = run_stage_handler(hybrid.stage_port_scan, run)
    assert stage.status == "failed" and stage.error.startswith("Could not start nmap:")

    calls = []
    def flaky(command, timeout):
        calls.append(command)
        if len(calls) == 2:
            raise PermissionError(13, "Permission denied", command[0])
        with open(report_path(command), "w", encoding="utf-8") as fh:
            fh.write(json.dumps([{"target": command[-1], "http_status": 200, "plugins": {"HTTPServer": {"string": ["nginx"]}}}]))
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)
    fake_tools(monkeypatch, flaky)
    run = make_run(id="qaos00000002", target="10.0.0.5", status="running", tools=["nmap", "whatweb", "nikto"],
                   stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                           StageResult(stage="web_fingerprint", tool="whatweb"),
                           StageResult(stage="web_vuln_scan", tool="nikto")])
    context = {"web_ports": [PortFinding(host="10.0.0.5", port=80, service="http", is_web=True),
                             PortFinding(host="10.0.0.5", port=8080, service="http", is_web=True)]}
    stage = run_stage_handler(hybrid.stage_web_fingerprint, run, context, stage_index=1)
    assert stage.status == "completed"
    assert [w.reachable for w in run.web] == [True]  # a probe that never started records no result
    assert "Could not start whatweb" in stage.error
    # Nikto only scans the URL that answered WhatWeb, so the context hand-off survived the failure too.
    nikto_calls = []
    def nikto(command, timeout):
        nikto_calls.append(command)
        with open(report_path(command), "w", encoding="utf-8") as fh:
            fh.write(json.dumps([{"host": "10.0.0.5", "vulnerabilities": [{"msg": "X-Frame-Options header is not present.", "url": "/"}]}]))
        return CommandResult(command=command, exit_code=0, stdout="", stderr="", duration_seconds=0.1)
    fake_tools(monkeypatch, nikto)
    stage = run_stage_handler(hybrid.stage_web_vuln_scan, run, context, stage_index=2)
    assert stage.status == "completed" and len(nikto_calls) == 1 and "http://10.0.0.5" in nikto_calls[0]
    assert [v.url for v in run.vulns] == ["http://10.0.0.5/"]


def test_highlights_do_not_repeat_the_same_finding():
    """The same Nikto finding on several URLs (nginx outdated on :80 and :443) was listed once per URL and
    pushed distinct findings out of the three finding slots."""
    outdated = "nginx/1.18.0 appears to be outdated (current stable is 1.26.x)."
    run = make_run(id="qahl00000001", tools=["nikto"], vulns=[
        VulnFinding(url=f"http://10.0.0.5:{port}", severity="medium", description=outdated) for port in (80, 443, 8080)
    ] + [VulnFinding(url="http://10.0.0.5/admin", severity="high", description="Admin console is reachable."),
         VulnFinding(url="http://10.0.0.5/x", severity="medium", description="Clickjacking: X-Frame-Options missing.")])
    highlights = hybrid.summarize(run).highlights
    findings = [h for h in highlights if h.startswith("[")]
    assert findings == ["[high] Admin console is reachable.", f"[medium] {outdated}",
                        "[medium] Clickjacking: X-Frame-Options missing."]


# --- Settings and the .env writer -----------------------------------------------------------------

def test_env_write_retries_a_windows_sharing_violation(monkeypatch, tmp_path):
    """Settings are re-read from .env on every request; on Windows os.replace() fails with PermissionError
    while such a read has the file open. The writer must wait it out instead of answering 500."""
    env = tmp_path / "retry.env"
    env.write_text("A=old\n", encoding="utf-8")
    real_replace = envfile.os.replace
    attempts = []
    def flaky_replace(source, target):
        attempts.append(source)
        if len(attempts) < 3:
            raise PermissionError(5, "Access is denied", str(target))
        real_replace(source, target)
    monkeypatch.setattr(envfile.os, "replace", flaky_replace)
    monkeypatch.setattr(envfile.time, "sleep", lambda seconds: None)
    update_env_file(env, {"A": "new"})
    assert len(attempts) == 3 and env.read_text(encoding="utf-8") == "A=new\n"
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]

    # A persistent failure still surfaces as an error and leaves no temporary file behind.
    monkeypatch.setattr(envfile, "_REPLACE_ATTEMPTS", 2)
    def always_fails(source, target):
        raise PermissionError(5, "Access is denied", str(target))
    monkeypatch.setattr(envfile.os, "replace", always_fails)
    with pytest.raises(PermissionError):
        update_env_file(env, {"A": "newer"})
    assert env.read_text(encoding="utf-8") == "A=new\n"
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]


def test_concurrent_settings_saves_all_succeed(client):
    """Parallel saves from the dashboard (plus the per-request settings reload) must all answer 200 and leave
    one line per key. On Windows this exercises the os.replace retry for real."""
    env_path = Path(ENV_FILE)
    errors = []
    def save(i):
        body = ({"max_top_ports": 200 + i} if i % 3 == 0 else {"anthropic_model": f"model-{i}"} if i % 3 == 1
                else {"allowed_targets": [f"10.0.{i}.0/24"]})
        resp = client.put("/api/settings", json=body)
        if resp.status_code != 200:
            errors.append((resp.status_code, resp.text[:120]))
    threads = [threading.Thread(target=save, args=(i,)) for i in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    try:
        assert errors == []
        text = env_path.read_text(encoding="utf-8")
        for key in ("HYBRIDSEC_MAX_TOP_PORTS", "ANTHROPIC_MODEL", "HYBRIDSEC_ALLOWED_TARGETS"):
            assert sum(1 for line in text.splitlines() if line.startswith(f"{key}=")) == 1, key
        assert text.count(envfile._ADDED_KEYS_HEADER) == 1
    finally:
        client.put("/api/settings", json={"max_top_ports": 1000, "anthropic_model": "", "allowed_targets": []})


def test_added_keys_header_is_written_once(tmp_path):
    """Every save that appended a new key used to add another "added from the dashboard" comment block."""
    env = tmp_path / "h.env"
    env.write_text("A=1\n", encoding="utf-8")
    update_env_file(env, {"B": "2"})
    update_env_file(env, {"C": "3"})
    update_env_file(env, {"D": "4", "B": "22"})
    text = env.read_text(encoding="utf-8")
    assert text.count(envfile._ADDED_KEYS_HEADER) == 1
    assert [line for line in text.splitlines() if "=" in line] == ["A=1", "B=22", "C=3", "D=4"]


def test_hand_edited_limits_are_clamped_to_the_api_range(client):
    """A .env edited by hand with a zero, a negative number or a default above the maximum must not make every
    run request fail; the values are clamped to the range the Settings API itself enforces."""
    update_env_file(ENV_FILE, {"HYBRIDSEC_MAX_TOP_PORTS": "0", "HYBRIDSEC_MAX_TIMEOUT": "-5",
                               "HYBRIDSEC_DEFAULT_TIMEOUT": "99999", "HYBRIDSEC_AI_TIMEOUT": "0"})
    try:
        settings.reload()
        assert (settings.max_top_ports, settings.max_timeout_seconds, settings.default_timeout_seconds,
                settings.ai_timeout_seconds) == (1, 10, 10, 1)
        health = client.get("/api/health").json()["limits"]
        assert health["default_timeout_seconds"] <= health["max_timeout_seconds"]
        resp = start_run(client)  # no timeout in the request: the clamped default applies
        assert resp.status_code == 202, resp.text
        assert wait_for_run(client, resp.json()["id"])["status"] == "completed"
    finally:
        update_env_file(ENV_FILE, {"HYBRIDSEC_MAX_TOP_PORTS": "", "HYBRIDSEC_MAX_TIMEOUT": "",
                                   "HYBRIDSEC_DEFAULT_TIMEOUT": "", "HYBRIDSEC_AI_TIMEOUT": ""})
        settings.reload()


# --- Reports --------------------------------------------------------------------------------------

class _TextOnly(HTMLParser):
    """Collects the text nodes and the tag names of an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.tags: set[str] = set()

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)

    def handle_data(self, data):
        self.text.append(data)


def test_reports_survive_hostile_scanner_output():
    """Banners with markup, quotes, formula prefixes, backticks, pipes, RTL marks and very long strings stay
    literal text in every format: no script tag, no spreadsheet formula, no broken Markdown table."""
    rtl = "\u202eevil\u202c"  # right-to-left override and pop-directional, written as escapes
    long_banner = "A" * 5000
    run = make_run(
        id="qarep0000001", label='<img src=x onerror=alert(1)> "quoted"', tools=["nmap", "whatweb", "nikto"],
        ports=[PortFinding(host="10.0.0.5", port=80, service="http", product="=HYPERLINK(\"x\")", version="-1.0",
                           extra=f"<script>alert(1)</script> {rtl} {long_banner}")],
        web=[WebFinding(url="http://10.0.0.5", host="10.0.0.5", port=80, status_code=200, title="+cmd|' `tick`",
                        technologies=[{"name": "<b>nginx</b>", "version": "@SUM(1)"}, {"version": "no name"}])],
        vulns=[VulnFinding(url="http://10.0.0.5/</td>", severity="a|b", description="x | y ``` <script>",
                           reference="-@=")],
        log=["```", "</pre><script>alert(1)</script>"],
    )
    run.summary = hybrid.summarize(run)

    html = render_html(run)
    parsed = _TextOnly()
    parsed.feed(html)
    assert "script" not in parsed.tags and "img" not in parsed.tags
    text = "".join(parsed.text)
    assert "<script>alert(1)</script>" in text and rtl in text and long_banner in text
    assert "None" not in html.split("Web technologies")[1].split("Findings")[0]

    rows = list(csv.reader(io.StringIO(render_csv(run))))
    assert all(not cell or cell[0] not in "=+-@\t\r" for row in rows for cell in row)
    assert any("'=HYPERLINK" in cell for row in rows for cell in row)

    md = render_markdown(run)
    finding_row = next(line for line in md.splitlines() if "x \\| y" in line)
    assert len(re.findall(r"(?<!\\)\|", finding_row)) == 5 and "a\\|b" in finding_row  # 4 cells, pipes escaped
    assert "\\`tick\\`" in md and md.count("\n```\n") == 2
    # Custom tool output is hostile text too: escaped in HTML, one CSV row per call, fenced safely in Markdown.
    hostile = run.model_copy(deep=True, update={
        "custom_tools": {"hdrcheck": CustomTool(name="hdrcheck", program="curl", args=["-sI", "{url}"], scope="url",
                                                created_at=run.created_at)},
        "custom_outputs": [CustomToolOutput(tool="hdrcheck", target="http://10.0.0.5", command="curl -sI http://10.0.0.5",
                                            exit_code=0, stdout='<script>alert(1)</script>\n```\n=HYPERLINK("x")\n|a|b|',
                                            stderr="-warn")]})
    parsed = _TextOnly()
    parsed.feed(render_html(hostile))
    assert "script" not in parsed.tags and "<script>alert(1)</script>" in "".join(parsed.text)
    rows = list(csv.reader(io.StringIO(render_csv(hostile))))
    assert all(len(row) == 15 for row in rows) and [row[0] for row in rows].count("tool_output") == 1
    assert all(not cell or cell[0] not in "=+-@\t\r" for row in rows for cell in row)
    custom_md = render_markdown(hostile)
    assert custom_md.count("\n```\n") == 4 and "\n```\n=HYPERLINK" not in custom_md
