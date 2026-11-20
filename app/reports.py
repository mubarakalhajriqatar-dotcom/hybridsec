"""Report rendering: JSON, CSV, Markdown and a self-contained HTML page for one run.

GET /api/runs/{id}/report calls render() with the requested format. Scanner output is untrusted text (a web
page title or a Nikto message can contain anything), so every format escapes it: CSV cells are protected
against spreadsheet formula injection, Markdown against table and code-fence breakers, and HTML with
html.escape on every value. Custom tool output (tools/custom.py) is cleaned of control characters when it is
captured and escaped here like everything else; its section only appears for a run that used custom tools.
"""
from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timezone
from typing import Any

from .schemas import CustomToolOutput, Run
from .tools.custom import CUSTOM_STAGE, RUN_OUTPUT_CHARS, STDOUT_CHARS
from .tools.registry import TOOLS, profile_label

# Report format name -> media type. The report endpoint only accepts these keys.
FORMATS = {"json": "application/json", "csv": "text/csv", "md": "text/markdown", "html": "text/html"}


def filename(run: Run, fmt: str) -> str:
    """Download file name, e.g. hybridsec-127.0.0.1-20260101-120000.html (unsafe characters become "_"). Only
    ASCII letters and digits are kept: the name goes into a Content-Disposition header, which must be Latin-1."""
    stamp = run.created_at.strftime("%Y%m%d-%H%M%S")
    safe_target = "".join(ch if (ch.isascii() and ch.isalnum()) or ch in "-._" else "_" for ch in run.target)
    return f"hybridsec-{safe_target}-{stamp}.{fmt}"


def render(run: Run, fmt: str) -> str:
    """Render `run` in one of FORMATS."""
    if fmt == "json":
        return run.model_dump_json(indent=2)
    if fmt == "csv":
        return render_csv(run)
    if fmt == "md":
        return render_markdown(run)
    if fmt == "html":
        return render_html(run)
    raise ValueError(f"Unsupported format: {fmt}. Use one of {', '.join(FORMATS)}.")


def _format_datetime(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "-"


def coverage_label(run: Run) -> str:
    """How complete the run's findings are: complete, partial (a stage with gaps), failed (the run failed) or
    in progress. Every CSV row carries it, because the CSV has no status column."""
    if run.status == "failed":
        return "failed"
    if run.status in ("queued", "running"):
        return "in progress"
    return "partial" if run.summary.partial else "complete"


def tools_with_profiles(run: Run) -> str:
    """The run's tools with the profile each one used, as "nmap (Quick port scan), whatweb (Stealthy, level 1)".
    A run recorded before profiles existed lists its tools alone."""
    return ", ".join(f"{tool} ({profile_label(tool, run.profiles[tool])})" if run.profiles.get(tool)
                     else f"{tool} (custom)" if tool in run.custom_tools else tool
                     for tool in run.tools)


def _status_label(run: Run) -> str:
    """The run status, with "(partial results)" added to a completed run that has gaps."""
    return f"{run.status} (partial results)" if coverage_label(run) == "partial" else run.status


def _notice(run: Run) -> tuple[str, str] | None:
    """Heading and text of the warning that opens a report whose findings cannot be taken as complete: the
    run failed, is still executing, or completed with gaps. None for a complete run."""
    if run.status == "failed":
        return "Run failed.", run.error or "See the stage notes."
    if _pending(run):
        return ("Run in progress.", "This report was made while the run was still executing: the summary is "
                "computed when the run ends, and the stages still to come may add results.")
    if coverage_label(run) != "partial":
        return None
    notes = [_sentence(f"{stage.tool}: {stage.error}") for stage in run.stages
             if (stage.partial or stage.status == "failed") and stage.error and stage.stage != CUSTOM_STAGE]
    return ("Partial results.",
            " ".join(notes) or "A stage did not examine everything it was given; see the stage notes.")


def _pending(run: Run) -> bool:
    """True while the run is queued or executing. Its summary is only computed when it ends."""
    return run.status in ("queued", "running")


def _count(run: Run, value: int) -> str:
    """A summary count, or "-" where a number would mislead, by the rule the dashboard uses: while the run
    executes its summary is still the empty one (a zero would contradict the ports already listed below it),
    and a failed run that found nothing established nothing ("0 open ports" would read as a clean host)."""
    return "-" if _pending(run) or (run.status == "failed" and not value) else str(value)


def _seconds(value: float | None) -> str:
    """A duration, or "-" for a run or stage that has not finished (or never ran)."""
    return "-" if value is None else f"{value}s"


def _empty_text(run: Run, tool: str, found: str, absent: str, pending: str, failed: str) -> str:
    """What an empty result section says, so that nothing reads as a clean result unless it is one: `found`
    only when the tool's stage ran to the end and recorded nothing; otherwise that the workflow has no such
    stage (`absent`), why the stage did not run or failed, that the run is still executing (`pending`), or
    that it failed before the stage produced anything (`failed`). A stage skipped because the first stage failed
    gets `failed` too, as on the dashboard: its own reason ("No web services were discovered") would read as a
    result the run never got far enough to produce."""
    if tool not in run.tools:
        return absent
    stage = next((s for s in run.stages if s.tool == tool), None)
    status = stage.status if stage is not None else ("completed" if run.status == "completed" else "pending")
    name = TOOLS[tool].display_name if tool in TOOLS else tool
    if status in ("completed", "simulated"):
        return found
    if status == "skipped" and _first_stage_failed(run):
        return failed
    if status == "skipped":
        return f"{name} did not run: {stage.error or 'nothing to scan.'}"
    if status == "failed":
        return f"{name} failed: {stage.error or 'no output.'}"
    return pending if _pending(run) else failed


def _first_stage_failed(run: Run) -> bool:
    """True when the run failed because its first stage failed, so the later stages had no input to work on."""
    return run.status == "failed" and bool(run.stages) and run.stages[0].status == "failed"


def _empty_ports(run: Run) -> str:
    return _empty_text(run, "nmap", "No open ports found.", "This workflow has no port scan (Nmap).",
                       "Open ports appear when the port scan completes.",
                       "The run failed before the port scan produced results.")


def _empty_web(run: Run) -> str:
    return _empty_text(run, "whatweb", "No web services fingerprinted.",
                       "This workflow has no web fingerprinting (WhatWeb).",
                       "Web technologies appear when WhatWeb finishes.",
                       "The run failed before WhatWeb produced results.")


def _empty_findings(run: Run) -> str:
    return _empty_text(run, "nikto", "No findings recorded.", "This workflow has no web vulnerability scan (Nikto).",
                       "Findings appear when Nikto finishes.", "The run failed before Nikto produced results.")


def _sentence(text: str) -> str:
    """`text` ending with a full stop, so that notes placed one after another never run together."""
    return text if text.endswith((".", "!", "?")) else text + "."


# Custom tool output: kept as text, never parsed into findings or scored.
_CUSTOM_NOTE = "Kept as each tool printed it (control characters removed). Not parsed into findings or scored."


def _output_text(output: CustomToolOutput) -> str:
    """A call's standard output, followed by its standard error when there is any."""
    return output.stdout + (f"\n--- stderr ---\n{output.stderr}" if output.stderr else "")


# How a call ended (CustomToolOutput.ended) when it did not exit by itself. Only a program that exited has an exit
# code of its own; HybridSec stopped the others, could not start them, or (simulation) never started them.
_ENDED_TEXT = {
    "time_limit": "stopped at the time limit",
    "output_limit": f"stopped for printing more than {STDOUT_CHARS:,} characters",
    "shutdown": "stopped by the server shutdown",
    "not_started": "could not be started",
    "simulated": "simulated, not started",
}


def _ended(output: CustomToolOutput, simulated: bool = False) -> str:
    """How the call ended. A call saved before `ended` existed reads as "exited": in a `simulated` run, which never
    starts a custom tool, it was simulated (its stored exit code 0 was made up), as the dashboard shows it; otherwise
    timed_out was the only stop recorded, at the time limit."""
    if output.ended != "exited":
        return output.ended
    if simulated:
        return "simulated"
    return "time_limit" if output.timed_out else "exited"


def _output_status(output: CustomToolOutput, simulated: bool = False) -> str:
    """How a call ended, as "exit code 0" or "stopped at the time limit", plus a note when its output was cut: by
    the run's limit on custom-tool output (run_limit), which may have left none of it, or at the limit per call.
    `simulated` is True for a call of a run in simulation mode (see _ended)."""
    ended = _ended(output, simulated)
    status = _ENDED_TEXT.get(ended) or ("no exit code" if output.exit_code is None else f"exit code {output.exit_code}")
    if output.run_limit:
        cut = ("output cut: the run reached" if _output_text(output)
               else "output not kept: the run had already reached")
        return f"{status}; {cut} its limit of {RUN_OUTPUT_CHARS:,} characters of custom-tool output"
    if output.truncated and ended != "output_limit":  # a stop for printing too much says so already
        return status + "; output truncated"
    return status


def _no_output(output: CustomToolOutput) -> str | None:
    """What a report says in place of a call's output when none was kept, or None when the status already says
    why (the run's limit on custom-tool output was reached) or there is output to show."""
    if _output_text(output) or output.run_limit:
        return None
    if output.truncated:
        return "Nothing printable was kept: the output was cut at a limit."
    return "The tool printed nothing."


def _empty_custom(run: Run) -> str:
    """What the custom tool section says when no call recorded output."""
    if _pending(run):
        return "Custom tool output appears when the run reaches those stages."
    return "No custom tool produced output; the workflow stages above say why."


def _score_text(run: Run) -> str:
    """The risk score cell of the Markdown summary: only a completed run has been scored."""
    return f"{run.summary.risk_score}/100" if run.status == "completed" else "not scored"


def _html_risk(run: Run) -> str:
    """The risk score tile of the HTML report, with its bar; a run that did not complete is not scored."""
    score = run.summary.risk_score
    if run.status != "completed":
        return "<div class='kpi'><b>-</b><span>Risk score (not scored)</span></div>"
    return (f"<div class='kpi'><b>{score}<small>/100</small></b><span>Risk score</span>"
            f"<div class='risk'><i style='width:{score}%;background:{_risk_color(score)}'></i></div></div>")


def _no_highlights(run: Run) -> str:
    """What the Highlights section says when a run has none."""
    if run.status == "failed":
        return "The run failed, so no highlights were produced."
    if run.status in ("queued", "running"):
        return "Highlights appear when the run completes."
    return "No highlights were produced."


def _md_notice(run: Run) -> list[str]:
    """The notice as Markdown lines (a block quote and a blank line), or nothing."""
    notice = _notice(run)
    return [f"> **{notice[0]}** {_md_escape(notice[1])}", ""] if notice else []


def _html_notice(run: Run) -> str:
    """The notice as an HTML block, or an empty string."""
    notice = _notice(run)
    return f"<div class='notice'><b>{html.escape(notice[0])}</b> {html.escape(notice[1])}</div>" if notice else ""


# --- CSV ------------------------------------------------------------------------------------------

def _csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection: text starting with = + - @ tab or CR gets a leading quote.

    Without this, a page title such as =HYPERLINK(...) would run as a formula when the report is opened
    in Excel or LibreOffice.
    """
    if isinstance(value, str) and value and value[0] in "=+-@\t\r":
        return "'" + value
    return value


class _FormulaSafeWriter:
    """Wraps a csv.writer so that every cell passes through _csv_safe()."""

    def __init__(self, writer: Any) -> None:
        self._writer = writer

    def writerow(self, row: list[object]) -> None:
        self._writer.writerow([_csv_safe(cell) for cell in row])


def render_csv(run: Run) -> str:
    """One flat table for spreadsheets: a row per port, per technology and per finding, told apart by `section`."""
    buffer = io.StringIO()
    writer = _FormulaSafeWriter(csv.writer(buffer, lineterminator="\n"))
    # Every row says whether the data is live or simulated and whether the run's coverage was complete, so an
    # export is never mistaken for real or complete data once it is separated from the dashboard.
    mode = run.mode
    coverage = coverage_label(run)
    writer.writerow(["section", "host", "port", "protocol", "service", "product", "version", "url",
                     "technology", "tech_version", "severity", "description", "reference", "coverage", "mode"])
    # A port row's description holds Nmap's extra information (OS hints, script notes); a web row's holds the
    # page title, or "No HTTP response" for a service that never answered.
    for port in run.ports:
        writer.writerow(["port", port.host, port.port, port.protocol, port.service, port.product, port.version,
                         "", "", "", "", port.extra, "", coverage, mode])
    for web in run.web:
        page = web.title or ("" if web.reachable else "No HTTP response")
        if not web.technologies:
            writer.writerow(["web", web.host, web.port, "tcp", "", "", "", web.url, "", "", "", page, "",
                             coverage, mode])
        for tech in web.technologies:
            writer.writerow(["web", web.host, web.port, "tcp", "", "", "", web.url, tech.get("name", ""),
                             tech.get("version", tech.get("string", "")), "", web.title or "", "", coverage, mode])
    for vuln in run.vulns:
        writer.writerow(["vuln", "", "", "", "", "", "", vuln.url, "", "", vuln.severity, vuln.description,
                         vuln.reference, coverage, mode])
    # One row per custom tool call. The CSV stays a findings table: the output itself is in the other formats, and
    # a call none of whose output was kept says why instead of pointing there.
    for output in run.custom_outputs:
        is_url = output.target.startswith(("http://", "https://"))
        where = "The output is in the JSON, HTML and Markdown reports." if _output_text(output) else _no_output(output)
        status = _output_status(output, mode == "simulated")
        writer.writerow(["tool_output", "" if is_url else output.target, "", "", "", output.tool, "",
                         output.target if is_url else "", "", "", "",
                         " ".join(filter(None, [_sentence(status), where])), "", coverage, mode])
    if not (run.ports or run.web or run.vulns):
        # Without a single result row the export would be a bare header: a run row still says what the run
        # was and how it ended, so a failed or empty run is never mistaken for a clean one.
        if run.status == "failed":
            outcome = run.error or "The run failed."
        elif run.status in ("queued", "running"):
            outcome = "The run has not finished yet."
        else:
            outcome = "No open ports, web services or findings were recorded."
        writer.writerow(["run", run.target, "", "", "", "", "", "", "", "", "", outcome, "", coverage, mode])
    return buffer.getvalue()


# --- Markdown -------------------------------------------------------------------------------------

def _md_escape(value: object) -> str:
    """Escape text for a Markdown table cell or inline position: no pipes, backticks, links, raw HTML or newlines."""
    text = str(value if value is not None else "")
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    text = text.replace("<", "&lt;").replace(">", "&gt;").replace("*", "\\*").replace("_", "\\_")
    text = text.replace("[", "\\[").replace("]", "\\]")  # no [text](url) links from tool output
    return " ".join(text.split())


def _fence_safe(line: str) -> str:
    """Break up ``` inside a log line so it cannot close the report's code block early."""
    return line.replace("```", "` ` `")


def render_markdown(run: Run) -> str:
    """A Markdown report with the same sections as the HTML one."""
    summary = run.summary
    lines = [
        "# HybridSec assessment report",
        "",
        f"**Target:** `{_md_escape(run.target)}`  ",
        f"**Run ID:** `{_md_escape(run.id)}`  ",
        f"**Label:** {_md_escape(run.label or '-')}  ",
        f"**Mode:** {run.mode}  ",
        f"**Status:** {_status_label(run)}  ",
        f"**Tools:** {_md_escape(tools_with_profiles(run))}  ",
        f"**Started:** {_format_datetime(run.started_at)}  ",
        f"**Duration:** {_seconds(run.duration_seconds)}  ",
        "",
        *_md_notice(run),
        "## Summary",
        "",
        "| Hosts up | Open ports | Web services | Technologies | Findings | Risk score |",
        "|---|---|---|---|---|---|",
        f"| {_count(run, summary.hosts_up)} | {_count(run, summary.open_ports)} | {_count(run, summary.web_services)} "
        f"| {_count(run, summary.technologies)} | {_count(run, summary.vulnerabilities)} | {_score_text(run)} |",
        "",
        "### Highlights",
        "",
        *([f"- {_md_escape(highlight)}" for highlight in summary.highlights] or [f"_{_no_highlights(run)}_"]),
        "",
        "## Workflow stages",
        "",
        "| # | Stage | Tool | Status | Duration | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for number, stage in enumerate(run.stages, start=1):
        lines.append(f"| {number} | {_md_escape(stage.stage)} | {_md_escape(stage.tool)} | {stage.status} "
                     f"| {_seconds(stage.duration_seconds)} | {_md_escape(stage.error or '')} |")

    lines += ["", "## Open ports", ""]
    if run.ports:
        lines += ["| Host | Port | Proto | Service | Product | Version | Extra |", "|---|---|---|---|---|---|---|"]
        lines += [f"| {_md_escape(port.host)} | {port.port} | {_md_escape(port.protocol)} | {_md_escape(port.service)} "
                  f"| {_md_escape(port.product)} | {_md_escape(port.version)} | {_md_escape(port.extra)} |"
                  for port in run.ports]
    else:
        lines.append(f"_{_md_escape(_empty_ports(run))}_")

    lines += ["", "## Web technologies", ""]
    if run.web:
        for web in run.web:
            unreachable = "" if web.reachable else "  |  No HTTP response"
            lines += [f"### {_md_escape(web.url)}",
                      "",
                      f"Status: {web.status_code or '-'}  |  Title: {_md_escape(web.title or '-')}{unreachable}",
                      ""]
            for tech in web.technologies:
                detail = tech.get("version") or tech.get("string") or ""
                lines.append(f"- **{_md_escape(tech.get('name'))}** {_md_escape(detail)}".rstrip())
            lines.append("")
    else:
        lines.append(f"_{_md_escape(_empty_web(run))}_")

    lines += ["", "## Findings", ""]
    if run.vulns:
        lines += ["| Severity | URL | Description | Reference |", "|---|---|---|---|"]
        lines += [f"| {_md_escape(vuln.severity)} | {_md_escape(vuln.url)} | {_md_escape(vuln.description)} "
                  f"| {_md_escape(vuln.reference)} |" for vuln in run.vulns]
    else:
        lines.append(f"_{_md_escape(_empty_findings(run))}_")

    if run.custom_tools:
        lines += ["", "## Custom tool output", "", f"_{_md_escape(_CUSTOM_NOTE)}_", ""]
        for output in run.custom_outputs:
            lines += [f"### {_md_escape(output.tool + ' - ' + output.target)}", "",
                      f"Command: {_md_escape(output.command)}  |  "
                      f"{_md_escape(_output_status(output, run.mode == 'simulated'))}  |  "
                      f"Duration: {_seconds(output.duration_seconds)}", ""]
            if _output_text(output):
                lines += ["```", *[_fence_safe(line) for line in _output_text(output).split("\n")], "```", ""]
            elif _no_output(output):
                lines += [f"_{_md_escape(_no_output(output))}_", ""]
        if not run.custom_outputs:
            lines.append(f"_{_md_escape(_empty_custom(run))}_")

    lines += ["", "## Execution log", "", "```", *[_fence_safe(line) for line in run.log], "```", ""]
    if run.mode == "simulated":
        lines += ["", "> This run used simulation mode. The data is synthetic and did not come from the target.", ""]
    return "\n".join(lines)


# --- HTML -----------------------------------------------------------------------------------------

_CSS = """
body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f5f7fa;color:#1f2933}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px}
h1{margin:0 0 4px;font-size:26px}
h2{margin:32px 0 12px;font-size:19px;border-bottom:2px solid #e1e6ec;padding-bottom:6px}
h3{margin:18px 0 6px;font-size:15px}
.meta{color:#52606d;font-size:14px}.meta code{background:#e8edf2;padding:1px 6px;border-radius:4px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0}
.kpi{background:#fff;border:1px solid #e1e6ec;border-radius:8px;padding:14px}
.kpi b{display:block;font-size:24px}
.kpi span{font-size:12px;color:#52606d;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e1e6ec;font-size:13px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #eef1f4;vertical-align:top;overflow-wrap:break-word}
td.long{overflow-wrap:anywhere}
td.long code{white-space:pre-wrap}
th{background:#eef2f6}
tr:nth-child(even) td{background:#fafbfc}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase;
white-space:nowrap;overflow-wrap:normal}
.critical{background:#7f1d1d;color:#fff}.high{background:#dc2626;color:#fff}.medium{background:#f59e0b;color:#1f2933}
.low{background:#3b82f6;color:#fff}.info{background:#9ca3af;color:#fff}
.risk{height:10px;background:#e1e6ec;border-radius:5px;overflow:hidden}.risk i{display:block;height:100%}
.chip{display:inline-block;background:#e8edf2;border-radius:4px;padding:2px 7px;margin:2px;font-size:12px}
pre{background:#111827;color:#d1d5db;padding:14px;border-radius:8px;font-size:12px;overflow:auto}
.notice{background:#fff7ed;border:1px solid #fdba74;padding:10px 14px;border-radius:8px;margin-top:16px}
footer{margin-top:40px;color:#7b8794;font-size:12px}
"""


def _html_output(output: CustomToolOutput) -> str:
    """A call's output as a <pre> block, or the sentence that says why there is none (or nothing when its status
    line already says so)."""
    if _output_text(output):
        return f"<pre>{html.escape(_output_text(output))}</pre>"
    missing = _no_output(output)
    return f"<p>{html.escape(missing)}</p>" if missing else ""


def _risk_color(score: int) -> str:
    """Green below 30, amber below 70, red from 70."""
    return "#16a34a" if score < 30 else "#f59e0b" if score < 70 else "#dc2626"


def render_html(run: Run) -> str:
    """A self-contained HTML page (inline CSS, no scripts) that can be e-mailed or archived as it is."""
    esc = html.escape
    summary = run.summary
    kpis = [(summary.hosts_up, "Hosts up"), (summary.open_ports, "Open ports"), (summary.web_services, "Web services"),
            (summary.technologies, "Technologies"), (summary.vulnerabilities, "Findings")]
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>HybridSec report - {esc(run.target)}</title><style>{_CSS}</style></head><body><div class='wrap'>",
        "<h1>HybridSec assessment report</h1>",
        f"<p class='meta'>Target <code>{esc(run.target)}</code> &middot; Run <code>{esc(run.id)}</code> &middot; "
        f"{esc(run.label or '')} {esc(run.mode)} mode &middot; {esc(_status_label(run))} &middot; "
        f"tools: {esc(tools_with_profiles(run))} &middot; "
        f"started {_format_datetime(run.started_at)} &middot; {_seconds(run.duration_seconds)}</p>",
        _html_notice(run),
        "<div class='kpis'>",
        *[f"<div class='kpi'><b>{_count(run, value)}</b><span>{label}</span></div>" for value, label in kpis],
        _html_risk(run),
        "</div>",
        "<h2>Highlights</h2><ul>",
        *([f"<li>{esc(highlight)}</li>" for highlight in summary.highlights]
          or [f"<li>{esc(_no_highlights(run))}</li>"]),
        "</ul>",
        "<h2>Workflow stages</h2><table><tr><th>#</th><th>Stage</th><th>Tool</th><th>Status</th><th>Duration</th>"
        "<th>Command / notes</th></tr>",
    ]
    for number, stage in enumerate(run.stages, start=1):
        note = esc(stage.error or "")
        command = f"<code>{esc(stage.command)}</code>" if stage.command else ""
        parts.append(f"<tr><td>{number}</td><td>{esc(stage.stage)}</td><td>{esc(stage.tool)}</td>"
                     f"<td>{esc(stage.status)}</td><td>{_seconds(stage.duration_seconds)}</td>"
                     f"<td class='long'>{command}<br>{note}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>Open ports</h2>")
    if run.ports:
        parts.append("<table><tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th><th>Product</th>"
                     "<th>Version</th><th>Extra</th></tr>")
        parts.extend(
            f"<tr><td>{esc(port.host)}</td><td>{port.port}</td><td>{esc(port.protocol)}</td>"
            f"<td>{esc(port.service)}</td><td>{esc(port.product)}</td><td>{esc(port.version)}</td>"
            f"<td class='long'>{esc(port.extra)}</td></tr>"
            for port in run.ports
        )
        parts.append("</table>")
    else:
        parts.append(f"<p>{esc(_empty_ports(run))}</p>")

    parts.append("<h2>Web technologies</h2>")
    if run.web:
        for web in run.web:
            status = f"HTTP {web.status_code or '-'}" if web.reachable else "No HTTP response"
            parts.append(f"<h3>{esc(web.url)}</h3><p class='meta'>{status} &middot; "
                         f"{esc(web.title or '-')}</p><p>")
            for tech in web.technologies:
                detail = tech.get("version") or tech.get("string") or ""
                parts.append(f"<span class='chip'><b>{esc(str(tech.get('name') or ''))}</b> {esc(str(detail))}</span>")
            parts.append("</p>")
    else:
        parts.append(f"<p>{esc(_empty_web(run))}</p>")

    parts.append("<h2>Findings</h2>")
    if run.vulns:
        parts.append("<table><tr><th>Severity</th><th>URL</th><th>Description</th><th>Reference</th></tr>")
        parts.extend(
            f"<tr><td><span class='pill {esc(vuln.severity)}'>{esc(vuln.severity)}</span></td>"
            f"<td>{esc(vuln.url)}</td><td class='long'>{esc(vuln.description)}</td>"
            f"<td class='long'>{esc(vuln.reference)}</td></tr>"
            for vuln in run.vulns
        )
        parts.append("</table>")
    else:
        parts.append(f"<p>{esc(_empty_findings(run))}</p>")

    if run.custom_tools:
        parts.append(f"<h2>Custom tool output</h2><p class='meta'>{esc(_CUSTOM_NOTE)}</p>")
        parts.extend(f"<h3>{esc(output.tool)} &middot; {esc(output.target)}</h3><p class='meta'>"
                     f"<code>{esc(output.command)}</code> &middot; "
                     f"{esc(_output_status(output, run.mode == 'simulated'))} &middot; "
                     f"{_seconds(output.duration_seconds)}</p>{_html_output(output)}"
                     for output in run.custom_outputs)
        if not run.custom_outputs:
            parts.append(f"<p>{esc(_empty_custom(run))}</p>")

    parts.append("<h2>Execution log</h2><pre>" + esc("\n".join(run.log)) + "</pre>")
    if run.mode == "simulated":
        parts.append("<div class='notice'><b>Simulation mode.</b> This data is synthetic and did not come from the "
                     "target.</div>")
    parts.append(f"<footer>Generated by HybridSec on {_format_datetime(datetime.now(timezone.utc))}. "
                 "Only test systems you own or are authorized to assess.</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)
