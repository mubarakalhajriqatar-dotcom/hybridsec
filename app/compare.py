"""Diff two runs: which ports, technologies and findings appeared, disappeared or changed between them.

Used by GET /api/compare. Items are matched on keys chosen so that volatile details do not produce noise:
technologies are keyed on host, port, name and version (not the full URL, which may carry a session id
after a redirect), so a version upgrade shows as one removed and one added technology; findings are keyed
on the URL without its query (scheme, host and path) plus the description with its volatile values masked
(the ETag inode, size and mtime values Nikto copies into its text, which change whenever the file does).
Advisory ids and versions stay in the key, and two findings with the same key are counted, not merged, so a
second advisory on the same URL is never hidden. When either run failed, is still executing or has partial
results the response carries a note, because what a cut-short scan did not reach would otherwise read as a
port that closed or opened.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from .schemas import CompareResponse, PortFinding, Run, VulnFinding
from .storage import to_list_item
from .tools.parsers import host_address
from .tools.registry import TOOLS, profile_for_run, profile_label

# Values that change between scans of an unchanged finding, each masked as "#":
_VOLATILE_RES = (
    # ETag fields after a colon: "inode: 2cf6, size: 5a6d6b2ba1f9a" (bare hex, Nikto 2.1.6 and later) or
    # "inode: 0x10f8f2" (older)
    re.compile(r"\b(inodes?|size|mtime|etags?)(\s*:\s*)(?:0x)?[0-9a-f]+\b", re.IGNORECASE),
    # the same without a colon ("inode 12345"): a number only, so that an ordinary word after the label stays
    re.compile(r"\b(inodes?|size|mtime|etags?)(\s+)(?:0x[0-9a-f]+|[0-9a-f]*\d[0-9a-f]*)\b", re.IGNORECASE),
    # Nikto 2.1.4 and older: "ETag header found on server, fields: 0x10f8f2 0xbc6"
    re.compile(r"\b(fields)(\s*:\s*)(?:0x[0-9a-f]+\b\s*)+", re.IGNORECASE),
)
# "Uncommon header 'x-runtime' found, with contents: 0.0123": for a header that carries a per-request value
# (a timing, a request or trace id) the value changes on every scan; a version header keeps its value.
_HEADER_CONTENTS_RE = re.compile(r"(header '([^']*)' found, with contents:\s*)(.*)", re.IGNORECASE)
_PER_REQUEST_HEADER_RE = re.compile(r"runtime|request-?id|correlation|trace|span|cf-ray|amz-cf-id|served-by|timer|"
                                    r"duration|server-timing", re.IGNORECASE)
_TOKEN_WITH_DIGIT_RE = re.compile(r"\S*\d\S*")


def compare_runs(base: Run, other: Run) -> CompareResponse:
    """Compare `other` against `base`: "added" means present only in `other`, "removed" only in `base`."""
    ports_added, ports_removed, ports_changed = _diff_ports(base, other)

    base_tech, other_tech = _technologies_by_key(base), _technologies_by_key(other)
    tech_added = [other_tech[k] for k in sorted(other_tech.keys() - base_tech.keys())]
    tech_removed = [base_tech[k] for k in sorted(base_tech.keys() - other_tech.keys())]

    vulns_added = _unmatched(other.vulns, base.vulns)
    vulns_removed = _unmatched(base.vulns, other.vulns)

    return CompareResponse(
        base=to_list_item(base),
        other=to_list_item(other),
        ports_added=sorted(ports_added, key=lambda p: p.port),
        ports_removed=sorted(ports_removed, key=lambda p: p.port),
        ports_changed=sorted(ports_changed, key=lambda c: c["port"]),
        tech_added=tech_added,
        tech_removed=tech_removed,
        vulns_added=vulns_added,
        vulns_removed=vulns_removed,
        risk_delta=_risk_delta(base, other),
        note=" ".join(note for note in (_coverage_note(base, other), _tool_note(base, other),
                                        _custom_note(base, other), _profile_note(base, other)) if note) or None,
    )


def _risk_delta(base: Run, other: Run) -> int | None:
    """Risk score of `other` minus that of `base`, or None unless both runs completed: only a completed run is
    scored (the reports say "not scored" and the dashboard shows "-" for the others), so a running run's empty
    summary or an interrupted run's leftover score would give a meaningless difference."""
    if base.status != "completed" or other.status != "completed":
        return None
    return other.summary.risk_score - base.summary.risk_score


# What is wrong with a run's coverage, in the singular and in the plural ("Both runs ...").
_COVERAGE_PROBLEMS = {
    "failed": ("failed", "failed"),
    "executing": ("is still executing", "are still executing"),
    "partial": ("has partial results", "have partial results"),
}


def _coverage_problem(run: Run) -> str | None:
    """The key of the run's coverage problem in _COVERAGE_PROBLEMS, or None when its findings are complete."""
    if run.status == "failed":
        return "failed"
    if run.status in ("queued", "running"):
        return "executing"
    return "partial" if run.summary.partial else None


def _coverage_note(base: Run, other: Run) -> str | None:
    """A warning when either run's findings cannot be taken as complete: what such a run lacks did not
    necessarily change. None when both runs completed with full coverage."""
    problems = {label: _coverage_problem(run) for label, run in (("base", base), ("other", other))}
    problems = {label: key for label, key in problems.items() if key}
    if not problems:
        return None
    if len(problems) == 2 and len(set(problems.values())) == 1:
        subject = f"Both runs {_COVERAGE_PROBLEMS[problems['base']][1]}"
    else:
        parts = " and ".join(f"the {label} run {_COVERAGE_PROBLEMS[key][0]}" for label, key in problems.items())
        subject = parts[0].upper() + parts[1:]
    pronoun = "them" if len(problems) == 2 else "it"
    return (f"{subject} (see the stage notes), so anything missing from {pronoun} is not evidence that it "
            "disappeared or appeared.")


def _tool_note(base: Run, other: Run) -> str | None:
    """A warning when a tool ran in only one of the runs: everything it found then shows as added or removed,
    although the run without it never looked for it. None when both runs used the same tools. Custom tools are
    left out: their output is not compared at all (see _custom_note)."""
    custom = set(base.custom_tools) | set(other.custom_tools)
    only_base = [t for t in base.tools if t not in other.tools and t not in custom]
    only_other = [t for t in other.tools if t not in base.tools and t not in custom]
    if not only_base and not only_other:
        return None
    parts = [f"{_tool_names(only)} ran only in the {label} run"
             for label, only in (("base", only_base), ("other", only_other)) if only]
    they, them = ("they", "them") if len(only_base) + len(only_other) > 1 else ("it", "it")
    return (f"{' and '.join(parts)}, so what {they} found appears here as removed or added although the run "
            f"without {them} never looked for it.")


def _custom_note(base: Run, other: Run) -> str | None:
    """A note when either run used custom tools: their output is raw text and is never compared, and different
    custom tools mean the built-in stages shared the time budget differently. None without custom tools."""
    names = sorted(set(base.custom_tools) | set(other.custom_tools))
    if not names:
        return None
    note = f"Output of the custom tool(s) {', '.join(names)} is kept as raw text and is not compared."
    if set(base.custom_tools) != set(other.custom_tools):
        note += (" The runs used different custom tools, which share the time budget with the built-in tools, so "
                 "the built-in stages may have had different time.")
    return note


def _tool_names(tools: list[str]) -> str:
    """Display names joined for a sentence (\"Nmap\", \"Nmap and WhatWeb\", \"Nmap, WhatWeb and Nikto\"); a tool
    that is no longer in the catalogue keeps its recorded name."""
    names = [TOOLS[t].display_name if t in TOOLS else t for t in tools]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _profile_note(base: Run, other: Run) -> str | None:
    """A warning when the runs used different profiles for a tool they share. A quick port scan records no
    versions and a narrower Nikto profile reports fewer findings, so such a difference is a difference in
    how the target was examined, not a change on the target. A run recorded before profiles existed
    counts as having used the defaults. A tool that is no longer in the catalogue (a stored run may name
    one) has its recorded keys compared as text instead of failing the comparison."""
    differences = []
    for tool in base.tools:
        if tool not in other.tools:
            continue
        if tool in TOOLS:
            before, after = profile_for_run(tool, base.profiles).key, profile_for_run(tool, other.profiles).key
        else:
            before, after = base.profiles.get(tool, ""), other.profiles.get(tool, "")
            if not before or not after:  # no record on one side: nothing to compare it with
                continue
        if before != after:
            differences.append(f"{tool} ({profile_label(tool, before)} vs {profile_label(tool, after)})")
    if not differences:
        return None
    return (f"The runs used different profiles for {', '.join(differences)}, so some differences may come "
            "from the profile rather than from the target.")


def _diff_ports(base: Run, other: Run) -> tuple[list[PortFinding], list[PortFinding], list[dict[str, Any]]]:
    """Ports only in `other`, ports only in `base`, and ports in both whose service details changed."""
    base_ports = {_port_key(p): p for p in base.ports}
    other_ports = {_port_key(p): p for p in other.ports}
    added = [other_ports[k] for k in other_ports if k not in base_ports]
    removed = [base_ports[k] for k in base_ports if k not in other_ports]
    changed = []
    for key in base_ports.keys() & other_ports.keys():
        before, after = base_ports[key], other_ports[key]
        if (before.service, before.product, before.version) != (after.service, after.product, after.version):
            changed.append({
                "host": key[0], "port": key[1], "protocol": key[2],
                "before": {"service": before.service, "product": before.product, "version": before.version},
                "after": {"service": after.service, "product": after.product, "version": after.version},
            })
    return added, removed, changed


def _technologies_by_key(run: Run) -> dict[tuple, dict[str, Any]]:
    """Every technology seen on a reachable web service, keyed by (host, port, name, version)."""
    found: dict[tuple, dict[str, Any]] = {}
    for web in run.web:
        if not web.reachable:
            continue
        for tech in web.technologies:
            key = _tech_key(web.host, web.port, tech)
            found.setdefault(key, {"url": web.url, "name": tech.get("name", ""), "version": tech.get("version", "")})
    return found


def _port_key(port: PortFinding) -> tuple[str, int, str]:
    """The same port on the same address matches even if a hostname appears in only one of the runs."""
    return (host_address(port.host), port.port, port.protocol)


def _tech_key(host: str, port: int, tech: dict[str, Any]) -> tuple[str, int, str, str]:
    return (host, port, str(tech.get("name", "")).lower(), str(tech.get("version", "")))


def _unmatched(findings: list[VulnFinding], others: list[VulnFinding]) -> list[VulnFinding]:
    """The findings that have no counterpart in `others`, in their own order. Keys are counted: a run that
    reports the same finding twice where the other reports it once has one unmatched copy."""
    available = Counter(_vuln_key(v) for v in others)
    unmatched = []
    for vuln in findings:
        key = _vuln_key(vuln)
        if available[key]:
            available[key] -= 1
        else:
            unmatched.append(vuln)
    return unmatched


def _vuln_key(vuln: VulnFinding) -> tuple[str, str]:
    """Location (scheme, host and path, without query or trailing slash) plus the description with its ETag
    values masked. The scheme stays in the key because the same finding on http and on https are two findings;
    advisory ids (CVE-2021-41773, OSVDB-3233) and versions stay too, because they tell findings apart."""
    try:
        parts = urlsplit(vuln.url)
        location = f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/").lower()
    except ValueError:
        # urlsplit() rejects a host part with an unbalanced "[" ("Invalid IPv6 URL"). A damaged URL in a
        # stored finding must not make the comparison endpoint fail, so it is compared as plain text.
        location = vuln.url.strip().rstrip("/").lower()
    return (location, " ".join(_mask_volatile(vuln.description).split()).lower())


def _mask_volatile(text: str) -> str:
    """`text` with the values that change on every scan masked: ETag fields, and in the contents of a header
    that carries a per-request value every token holding a digit (x-powered-by: PHP/7.4.3 keeps its version)."""
    for pattern in _VOLATILE_RES:
        text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}#", text)

    def contents(match: re.Match[str]) -> str:
        if not _PER_REQUEST_HEADER_RE.search(match.group(2)):
            return match.group(0)
        return match.group(1) + _TOKEN_WITH_DIGIT_RE.sub("#", match.group(3))

    return _HEADER_CONTENTS_RE.sub(contents, text)
