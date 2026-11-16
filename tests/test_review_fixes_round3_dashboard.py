"""Regression tests for the third review round's dashboard fixes: one test per fixed defect, so none can come back.

The round covered presentation and readability only (dashboard/styles.css, dashboard/app.js and docs/DASHBOARD.md),
so every test here is a static check of those texts in the style of tests/test_review_fixes_round2.py section J.
The one exception evaluates a cut-out dashboard helper with `node` when it is installed. No scanner is launched
and no browser is opened.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app.config import BASE_DIR
from app.tools.custom import RUN_OUTPUT_CHARS, STDERR_CHARS, STDOUT_CHARS

DASHBOARD = BASE_DIR / "dashboard"
DOCS = BASE_DIR / "docs"


# --- Helpers ---------------------------------------------------------------------------------------

def _css() -> str:
    return (DASHBOARD / "styles.css").read_text(encoding="utf-8")


def _js() -> str:
    return (DASHBOARD / "app.js").read_text(encoding="utf-8")


def _rule(css: str, selector_pattern: str) -> str:
    """The declarations of the one single-line rule whose selector matches `selector_pattern` at a line start."""
    match = re.search(r"^" + selector_pattern + r" \{([^}]*)\}", css, re.MULTILINE)
    assert match, f"no rule for {selector_pattern!r} in dashboard/styles.css"
    return match.group(1)


def _wcag(a: str, b: str) -> float:
    """WCAG 2.x contrast ratio between two opaque #rrggbb colours."""
    def lum(h: str) -> float:
        c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        c = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _token(css: str, name: str) -> str:
    """The #rrggbb value of the --name custom property in :root."""
    match = re.search(r"--" + name + r": (#[0-9a-f]{6});", css)
    assert match, f"--{name} is not a six-digit hex token in dashboard/styles.css"
    return match.group(1)


def _over(fg: str, alpha: float, bg: str) -> str:
    """`fg` at `alpha` composited over the opaque `bg`, as #rrggbb (what a translucent --*-soft fill looks like)."""
    return "#" + "".join(f"{round(int(fg[i:i + 2], 16) * alpha + int(bg[i:i + 2], 16) * (1 - alpha)):02x}" for i in (1, 3, 5))


# --- A. Risk bars, Runs table, KPI grids -----------------------------------------------------------

def test_risk_bar_fill_is_a_block_box():
    """Requirement: the risk-bar fill is a block box, because width/height do not apply to an inline <span>."""
    assert "display: block" in _rule(_css(), r"\.risk-fill")


def test_runs_table_fits_a_1366px_laptop():
    """Requirement: the Runs table is compact, keeps its date on one line and hides the Tools column below 1440px,
    so every row stays one line tall on a 1366px laptop and the Delete button is never clipped."""
    js = _js()
    css = _css()
    assert '<table class="table table-compact runs-table">' in js
    assert '<th class="col-tools">Tools</th>' in js and '<td class="col-tools">' in js
    assert '<td class="col-date">' in js
    assert re.search(r"@media \(max-width: 1440px\) \{\n  \.runs-table \.col-tools \{ display: none; \}", css)
    assert ".runs-table .col-date { white-space: nowrap; }" in css
    assert ".runs-table .risk-bar { min-width: 80px; }" in css


def test_kpi_grids_never_leave_one_tile_alone():
    """Requirement: the Overview's four KPI tiles form a 2x2 grid and the run page's five tiles a 3-over-2 grid,
    so no tile sits alone on a row with empty cells beside it."""
    css = _css()
    assert "#overview-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }" in css
    assert "#run-kpis { grid-template-columns: repeat(6, minmax(0, 1fr)); }" in css
    assert "#run-kpis .kpi { grid-column: span 2; }" in css
    assert "#run-kpis .kpi:nth-child(n+4) { grid-column: span 3; }" in css
    phone = re.search(r"@media \(max-width: 560px\) \{\n(.*?)\n\}", css, re.DOTALL)
    assert phone, "the 560px media query is missing from dashboard/styles.css"
    assert "#run-kpis .kpi, #run-kpis .kpi:nth-child(n+4) { grid-column: auto; }" in phone.group(1)


# --- B. Contrast, focus, control heights, vertical rhythm ------------------------------------------

def test_faint_and_red_text_meet_wcag_aa():
    """Requirement: --text-faint (form hints, meta text) and --red-text (red pills, Delete buttons) reach the 4.5:1
    WCAG AA ratio for small text on every surface they appear on."""
    css = _css()
    for surface in ("bg", "bg-elev", "bg-elev-2"):
        assert _wcag(_token(css, "text-faint"), _token(css, surface)) >= 4.5, surface
        assert _wcag(_token(css, "red-text"), _over(_token(css, "red"), 0.16, _token(css, surface))) >= 4.5, surface
    assert "color: var(--red-text)" in _rule(css, r"\.pill-red")
    assert "color: var(--red-text)" in _rule(css, r"\.btn-danger")


def test_switch_shows_the_same_focus_outline_as_other_controls():
    """Requirement: a keyboard-focused toggle switch shows the 2px accent outline every other control uses, not an
    almost invisible translucent glow."""
    rule = _rule(_css(), r"\.switch input:focus-visible \+ \.switch-track")
    assert "outline: 2px solid var(--accent)" in rule
    assert "box-shadow" not in rule


def test_key_input_group_controls_share_one_height():
    """Requirement: the API-key input group stretches its controls to one height instead of forcing the eye button
    to a fixed 36px that matches neither the input nor the small buttons."""
    css = _css()
    assert "align-items: stretch" in _rule(css, r"\.input-group")
    assert "height" not in _rule(css, r"\.input-group \.btn-icon")


def test_kv_list_and_stacked_field_rows_keep_the_16px_rhythm():
    """Requirement: the <dl class="kv"> drops the browser's default margins and a stacked .field-row adds no row gap,
    so cards and stacked fields keep the 16px rhythm of the rest of the page."""
    css = _css()
    assert "margin: 0" in _rule(css, r"\.kv")
    row = _rule(css, r"\.field-row")
    assert "row-gap: 0" in row and "column-gap: var(--s-3)" in row


# --- C. Readability: documented conventions must hold, constants named once ------------------------

def test_router_entries_are_render_functions_that_take_the_route_sequence():
    """Requirement: app.js's CONVENTIONS hold: every view route() awaits is a render<Screen>(..., seq), and the
    old "render builds, paint writes" rule that the code contradicted is gone from the header and the docs."""
    js = _js()
    route_body = js.split("async function route() {", 1)[1].split("\n  }\n", 1)[0]
    entries = [line.split("await ", 1)[1].split("(", 1)[0] for line in route_body.splitlines() if "await " in line]
    assert len(entries) == 8 and all(n.startswith("render") for n in entries)  # renderTools is the eighth
    for n in entries:
        assert js.split("async function " + n + "(", 1)[1].split(")", 1)[0].split(",")[-1].strip() == "seq", n
    assert "Functions are verbs" not in js
    docs = (DOCS / "DASHBOARD.md").read_text(encoding="utf-8")
    assert "Naming is consistent on purpose" not in docs and "`render<Screen>(..., seq)`" in docs


def test_code_surface_colour_is_one_token_and_the_header_claims_only_what_holds():
    """Requirement: the code/log background is a single --bg-code token used by its three surfaces, and neither the
    stylesheet header nor the docs claim that every colour comes from a token."""
    css = _css()
    assert css.count("#070c16") == 1 and css.count("background: var(--bg-code)") == 3
    assert "every colour comes from a token" not in css
    assert "All colours and spacing come from" not in (DOCS / "DASHBOARD.md").read_text(encoding="utf-8")


def test_poll_interval_and_feedback_bounds_are_named_constants():
    """Requirement: the 2 s poll interval and the 3/2000-character feedback bounds are each written once, as a named
    constant, so the on-screen text can never disagree with the code."""
    js = _js()
    assert "const RUN_POLL_MS = 2000;" in js
    assert "schedule(2000)" not in js and js.count("schedule(RUN_POLL_MS)") == 2 and "every 2 seconds" not in js
    assert "const FEEDBACK_MIN = 3, FEEDBACK_MAX = 2000;" in js
    assert 'maxlength="2000"' not in js and "feedback.length < 3" not in js and "feedback.length > 2000" not in js


def test_default_tools_are_named_once_and_the_health_card_lists_the_servers_tools(tmp_path):
    """Requirement: the pre-checked tool pair is the DEFAULT_TOOLS constant, and the Service health card lists the
    tools /api/health reports instead of a hard-coded trio (ARCHITECTURE.md promises a new tool appears by itself).
    The retest's dashboard findings are pinned here too: the rules-planner hint describes the state instead of
    claiming that no key exists (and never contradicts a planner note), New Run refreshes the tool catalogue with the
    health, a failed run's tabs and the Overview tile do not promise data that will never arrive, the target
    placeholder admits IPv6, and the About page lists the two .env keys it left out. The third test round's are
    pinned as well: the history is not silently capped, New Run keeps the operator's tool choices, Clear key never
    claims to clear a key the environment still sets, one count rule everywhere, and readable labels. So are the
    defects the manual tests found: Execute this plan keeps a missing Nikto ticked, and the planner test's steps
    are numbered once. The fifth test round's too: how each custom-tool call ended, the run's limit on custom-tool
    output, unreadable and blocked custom tools, a null risk delta and the rules the Custom tools card states."""
    js = _js()
    assert 'const DEFAULT_TOOLS = ["nmap", "whatweb"];' in js
    assert 'name === "nmap"' not in js and "Object.keys(health.tools" in js
    assert js.count("DEFAULT_TOOLS.includes(") == 2
    assert "'\">' + esc(t) + \" \" + (ok ? \"installed\" : \"missing\")" in js   # the server's tool name is escaped
    assert "No API key configured" not in js
    assert js.count("The built-in rules planner is in use.") == 1 and 'plan.provider === "rules" && !plan.note' in js
    assert "Promise.allSettled([loadTools(true), loadHealth(true)])" in js
    assert "function noResultsText(run, found, pending, failed)" in js and js.count('noResultsText(run, ') == 5  # four tabs and the definition
    assert 'run.status === "completed" ? "No highlights' not in js and "The run failed before WhatWeb produced results." in js
    assert "const lastPorts = last && last.summary ? countFor(last, last.summary.open_ports) : null;" in js
    # The run list asks for the API's maximum and knows the true total; the Overview totals use /api/health.
    assert '"/api/runs?limit=" + RUN_LIST_LIMIT' in js and 'h.get("X-Total-Count")' in js
    assert "h.value.runs : null" in js and "function runsTruncatedText()" in js
    assert js.count("runsTruncatedText()") == 3  # the definition, the Runs page and the Compare pickers
    # Returning to New Run keeps the tools and profiles; only the first paint uses the defaults.
    assert 'syncRunTools($$("#run-tools .tool-row").length ? currentToolSelection() : null)' in js
    # The simulation default is set once, before the plan hand-off paints the tool rows: painted first, a plan's
    # Nikto that is not installed was unticked and dropped from the run on the first visit.
    render = js[js.index("async function renderNewRun("):js.index("async function submitRunForm(")]
    simulation_default = '$("#run-simulate").checked = allowed && !toolInstalled("nmap");'
    assert js.count(simulation_default) == 1
    assert render.index(simulation_default) < render.index("setRunPlan(q.plan_id, planTools);")
    # Flipping simulation off and on again: a box disabled meanwhile remembers whether it was meant to be ticked,
    # so a plan's Nikto comes back ticked and a tool the operator unticked stays unticked; neither is sent.
    assert '(disabled && checked ? " data-waiting" : "")' in js
    assert "waiting: $$('#run-tools input[name=\"tools\"][data-waiting]').map((input) => input.value)" in js
    assert "const preselected = keep ? keep.tools.concat(keep.waiting || []) : null;" in js
    assert "body = { target, authorized: true, tools, simulate:" in js and "selection.waiting" not in js
    # The server numbers the planner test's steps ("1. nmap (port_scan)"), so the list adds no numbers of its own.
    assert '\'<ul class="list-plain list-bare">\' + steps.map(' in js and '<ol class="list-plain">' not in js
    assert ".list-bare { list-style: none; padding-left: 0; }" in _css()
    # Clear key: the source of the key decides the pill, the button and the toast.
    assert 'view[row.source] === "environment"' in js and "if (view[row.flag]) toast(" in js
    assert 'putSettings(body, row.label + " cleared."' not in js
    # Readable stage names and run ids in the pickers.
    assert 'web_vuln_scan: "Web vulnerability scan"' in js and "esc(stageLabel(s.stage))" in js
    assert "Object.prototype.hasOwnProperty.call(STAGE_LABEL, key)" in js  # a stage named "constructor" stays text
    assert '(r.label ? "" : ", " + String(r.id).slice(0, 8))' in js
    # One rule for counts: a dash while a run executes, and for a failed run that found nothing.
    node = shutil.which("node")
    if node is not None:
        start = js.index("function countFor(")
        script = tmp_path / "counts.js"
        script.write_text(js[start:js.index("\n  }", start) + 4] + "\nconsole.log(JSON.stringify(["
                          "countFor({status: 'running'}, 3), countFor({status: 'failed'}, 0), countFor({status: 'failed'}, 4), "
                          "countFor({status: 'completed'}, 0), countFor({status: 'completed'}, undefined)]));\n", encoding="utf-8")
        proc = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30, check=False)
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout) == [None, None, 4, 0, None]
    html = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    assert 'placeholder="hostname, IP address or CIDR"' in html and "IPv4 address" not in html
    assert "HYBRIDSEC_MAX_CONCURRENT_RUNS=3" in html and "HYBRIDSEC_ALLOWED_HOSTS=" in html
    # The re-check's dashboard findings: every .env key on the About page, true wording about what Settings
    # edits and about the auto provider, a risk score only for completed runs, no dashes promised as zeros,
    # workflow-aware empty states, and a feedback label that does not contradict the planner note.
    assert all(f"{key}=" in html for key in ("HYBRIDSEC_AI_TIMEOUT", "HYBRIDSEC_HOST", "HYBRIDSEC_PORT"))
    assert "The same values can also be changed" not in html and "edited in <code>.env</code> only" in html
    assert "if its key is set" not in html and "<code>ant auth login</code> profile" in html
    assert 'r && r.status === "completed" && r.summary ? r.summary.risk_score : null' in js
    assert js.count("riskBar(shownRisk(") == 3 and "riskBar(s.risk_score)" not in js
    # The Custom tools page: the catalogue survives a 403 from another machine, Overview and the Planner stay
    # built-in only, a plan run cannot gain a custom tool, the partial notice and the delete call match the server,
    # and the name field has no pattern attribute (the browser compiles it with the v flag, where [a-z0-9_-] fails).
    assert 'api("/api/tools/custom").catch(() => null)' in js
    assert js.count("tools = (tools || []).filter((t) => !isCustomTool(t));") == 2
    assert 'const selectable = inPlan && (usable || !(name === "nikto" || isCustomTool(t)));' in js
    assert '"/api/tools/custom/" + encode(' in js and 's.stage !== "custom_tool"' in js
    tool_name = html[html.index('id="tool-name"'):]
    assert "pattern=" not in tool_name[:tool_name.index(">")]
    # The fifth round's: a call's status comes from how it ended (an exit code only when the program exited by
    # itself; an old simulated run's stored 0 is not one), the run-limit texts need run_limit, unreadable stored tools
    # are listed with Delete, a blocked program reads "refused", and a null risk delta is never shown as 0.
    assert 'const ended = o.ended && o.ended !== "exited" ? String(o.ended)' in js
    assert "Object.prototype.hasOwnProperty.call(words, ended)" in js
    assert 'outputBlockHtml(o, i, run.mode === "simulated")' in js
    assert 'outputBlockHtml(o, before.length + k, run.mode === "simulated")' in js
    assert 'if (o.run_limit) empty = "Nothing was kept: the run had already stored' in js
    assert 'o.truncated ? "Nothing was kept' not in js
    assert "renderCustomToolsList(list.value.tools, list.value.unreadable)" in js
    assert 'boolPill(t.installed, "installed", t.refused || t.blocked ? "refused" : "not installed")' in js
    assert 'if (t.blocked) return meta + (simulate ? ", simulated (its program is refused for live runs)"' in js
    assert "c.risk_delta !== null && c.risk_delta !== undefined" in js and "Number(c.risk_delta || 0)" not in js
    assert '"Not scored" + (baseRisk === null || otherRisk === null ? ": only completed runs have a risk score"' in js
    # The Program hint and the How custom tools run card state the rules the server applies, with its limits.
    refused_note = ("Known shells, interpreters and launchers, script files, attack tools and the built-in scanners "
                    "are always refused; the allow-list in .env decides the rest.")
    assert js.count(refused_note) == 1 and html.count(refused_note) == 1
    assert "const allowed = listed ? list.value.allowed_programs : [];" in js
    assert "lists only programs that are always refused" in js
    card = html[html.index("<li>They are added, listed and run only from the machine running HybridSec.</li>"):]
    card = card[:card.index("</ul>")]
    assert ("Fixed addresses, host names, <code>@server</code> forms, proxies, option files and network shares in the "
            "arguments are refused.") in card and "is not checked against the allowed scope" not in html
    # The output limit counts standard output and standard error each on its own, as the runner does.
    assert f"more than {STDOUT_CHARS:,} characters on standard output or on standard error" in card
    assert f"({STDERR_CHARS:,} characters of standard error are kept)" in card
    assert f"A run keeps at most {RUN_OUTPUT_CHARS:,} characters of custom-tool output in all." in card
    if node is not None:
        # A registered tool is shown with every value escaped: its arguments and description are operator text.
        def cut(start: str) -> str:
            begin = js.index(start)
            return js[begin:js.index("\n  }\n", begin) + 4]
        scope = js[js.index("const SCOPE_LABEL"):]
        script = tmp_path / "custom.js"
        script.write_text("\n".join([cut("function esc("), cut("function chips("), cut("function boolPill("),
                                      scope[:scope.index("\n")], cut("function customToolItemHtml("),
                                      cut("function unreadableToolItemHtml(")]) +
                          "\nconsole.log(customToolItemHtml({name: 'x', program: 'curl', args: ['<img/src=x/onerror=1>'],"
                          " scope: 'url', timeout_seconds: 30, installed: false, path: null, install_hint: 'hint',"
                          " description: '<b>d</b>'}));\n"
                          # A program that was found but whose file is refused, and a stored row that cannot be read.
                          "console.log(customToolItemHtml({name: 'y', program: 'curl', args: [], scope: 'target',"
                          " timeout_seconds: 30, installed: false, blocked: true, refused: false, path: null,"
                          " install_hint: 'Program: curl resolves to scan.bat'}));\n"
                          "console.log(unreadableToolItemHtml('Bad\"<name>'));\n", encoding="utf-8")
        proc = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30, check=False)
        assert proc.returncode == 0, proc.stderr
        assert "<img" not in proc.stdout and "&lt;img" in proc.stdout and "<b>d" not in proc.stdout
        assert 'data-delete-tool="x"' in proc.stdout and "once per web URL" in proc.stdout
        missing, blocked, unreadable = proc.stdout.splitlines()[-3:]
        assert ">not installed</span>" in missing and ">refused</span>" not in missing
        assert ">refused</span>" in blocked and "not installed" not in blocked and "resolves to scan.bat" in blocked
        assert '>unreadable</span>' in unreadable and ">Delete</button>" in unreadable and "<name>" not in unreadable
        assert 'data-delete-tool="Bad&quot;&lt;name&gt;"' in unreadable
        # The Tool output tab shows text the target controls (a page fetched by curl): every value is escaped too.
        active = js[js.index("const isActiveStatus"):]
        out = tmp_path / "output.js"
        out.write_text("\n".join([cut("function esc("), cut("function fmtDur("), cut("function emptyState("),
                                  active[:active.index("\n")], cut("function outputStatus("),
                                  cut("function renderOutputTab("), cut("function outputBlockHtml(")]) +
                       "\nconsole.log(renderOutputTab({status: 'completed', mode: 'live', custom_outputs: [{tool: 'x',"
                       " target: 'http://t/\"><svg onload=1>', command: 'curl <svg onload=2>', exit_code: 0,"
                       " duration_seconds: 1, stdout: '<img src=x onerror=alert(1)>', stderr: '<b>e</b>', truncated: true}]}));\n"
                       # How calls ended (the 7th is an old document of a simulated run), then four calls' blocks.
                       "console.log(JSON.stringify([{ended: 'output_limit', exit_code: null}, {ended: 'shutdown'},"
                       " {ended: 'not_started', exit_code: null}, {ended: 'simulated', exit_code: null},"
                       " {ended: 'exited', exit_code: 2}, {ended: 'exited', exit_code: null, timed_out: true},"
                       " {exit_code: 0}, {ended: 'constructor', exit_code: 4}]"
                       ".map((o, k) => outputStatus(o, k === 6))));\n"
                       "const mk = (o) => Object.assign({tool: 'x', target: 't', command: 'c', duration_seconds: 1,"
                       " stdout: '', stderr: ''}, o);\n"
                       "console.log(JSON.stringify([mk({truncated: true}), mk({truncated: true, run_limit: true}),"
                       " mk({stdout: 'kept', truncated: true, run_limit: true}), mk({})]"
                       ".map((o, k) => outputBlockHtml(o, k, false))));\n",
                       encoding="utf-8")
        proc = subprocess.run([node, str(out)], capture_output=True, text=True, timeout=30, check=False)
        assert proc.returncode == 0, proc.stderr
        assert "<img" not in proc.stdout and "<svg" not in proc.stdout and "<b>e" not in proc.stdout
        assert "&lt;img src=x onerror=alert(1)&gt;" in proc.stdout and 'id="run-output-0"' in proc.stdout
        statuses, blocks = (json.loads(line) for line in proc.stdout.splitlines()[-2:])
        assert statuses == ["stopped for printing too much", "stopped by the server shutdown", "could not start",
                            "simulated, not started", "exit 2", "stopped at its time limit", "simulated, not started",
                            "exit 4"]
        per_call, run_limit, run_limit_kept, nothing = blocks
        assert "Nothing printable was kept: the output was cut at a limit." in per_call
        assert "the run had already stored" not in per_call
        assert "The output was longer than the limit per call" in per_call
        assert "Nothing was kept: the run had already stored as much custom-tool output as it keeps." in run_limit
        assert "output-note" not in run_limit and ">truncated</span>" in run_limit
        assert "output-note" in run_limit_kept and "The run&#39;s limit on custom-tool output" in run_limit_kept
        assert "The tool printed nothing." in nothing and "truncated" not in nothing and "output-note" not in nothing
    # New output is appended below the existing blocks, so a pane the reader scrolled keeps its place.
    assert 'case "output": patchOutputTab(prev, run); break;' in js and 'list.insertAdjacentHTML("beforeend"' in js
    assert '"Not scored: the run failed"' in js and "gaugeHtml(s.risk_score)" not in js
    assert "const value = (n) => { const c = countFor(run, n);" in js
    assert "This workflow has no port scan. Add Nmap to discover open ports." in js
    assert "Add WhatWeb to the workflow to fingerprint web services." in js
    assert 'name + " did not run: "' in js and 'stageGap(run, "nikto", "Nikto")' in js
    assert 'stageGap(run, "whatweb", "WhatWeb")' in js and "The run failed before Nikto produced results." in js
    assert js.count("shownCount(r, s.") == 4 and 'const deltaText = !scored ? "-"' in js
    assert 'esc(unscored || "Not scored yet")) + \'">' in js and "not available" not in js
    assert 'plan.note ? "Feedback (not applied: see the planner note)" : "Feedback applied"' in js


def test_gauge_label_matches_risk_class_at_the_thresholds(tmp_path):
    """Requirement: the gauge word comes from riskClass(), so label and colour agree at 30 and 70."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed, so the JavaScript cannot be evaluated here")
    js = _js()
    assert "RISK_LABEL[cls]" in js and 'n < 30 ? "Low"' not in js

    def source(name: str) -> str:
        start = js.index("function " + name + "(")
        return js[start:js.index("\n  }", start) + 4]

    parts = [source(n) for n in ("esc", "riskClass", "gaugeHtml")]
    parts.append(js[js.index("const RISK_LABEL"):].split("\n", 1)[0])
    script = tmp_path / "gauge.js"
    script.write_text("\n".join(parts) + "\nconsole.log(JSON.stringify([29.9, 30, 69.9, 70].map((s) => gaugeHtml(s).split(' risk<')[0].split('>').pop())));\n", encoding="utf-8")
    proc = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == ["Low", "Moderate", "Moderate", "High"]
