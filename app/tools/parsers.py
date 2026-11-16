"""Parsers that turn raw scanner output into the structured findings defined in schemas.py.

Scanners get killed at time limits, change their output between versions, or print nothing at all, so the
parsers are tolerant: they salvage what they can from partial output instead of failing the whole stage.
This module also holds the rules that decide whether an open port is a web service and how to build its
URL, because both the live pipeline and the simulation need them.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from ..schemas import PortFinding, VulnFinding, WebFinding

# --- Web service detection ------------------------------------------------------------------------

# Nmap service names that are HTTP-like.
WEB_SERVICES = {"http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http", "ssl/https", "www", "webcache"}
# Ports that conventionally serve HTTP(S), even when Nmap could not name the service.
WEB_PORTS = {80, 81, 443, 591, 2082, 2083, 2086, 2087, 3000, 4443, 5000, 7001, 8000, 8008, 8080, 8081, 8088,
             8443, 8888, 9000, 9090, 9443, 10000}
TLS_HINTS = {"https", "ssl", "tls"}


def is_web_service(port: int, service: str, tunnel: str = "") -> bool:
    """True for HTTP-like services, which the later web stages should probe.

    A TLS tunnel alone is not enough (IMAPS, SMTPS and LDAPS use TLS but are not web), so a TLS port only
    counts when Nmap could not identify the service inside the tunnel.
    """
    name = (service or "").lower()
    if name in WEB_SERVICES or "http" in name or port in WEB_PORTS:
        return True
    if tunnel.lower() in TLS_HINTS:
        return name in {"", "unknown", "tcpwrapped"}
    return False


def is_tls(port: int, service: str, tunnel: str = "") -> bool:
    """True when the service should be reached with https:// rather than http://."""
    name = (service or "").lower()
    return tunnel.lower() in TLS_HINTS or "https" in name or "ssl" in name or port in {443, 4443, 8443, 9443}


def host_address(display_host: str) -> str:
    """The bare address from a PortFinding.host: "name (1.2.3.4)" gives "1.2.3.4"; an address stays as it is."""
    match = re.search(r"\(([^)]+)\)\s*$", display_host)
    return match.group(1) if match else display_host


def url_for(port: PortFinding, host_override: str | None = None) -> str:
    """The URL the web stages probe for an open port.

    https when the service looks like TLS, IPv6 addresses in brackets, and the port left out when it is
    the scheme's default (80 for http, 443 for https). `host_override` (the operator's hostname) replaces
    the scanned address so name-based virtual hosts answer for the intended site.
    """
    scheme = "https" if is_tls(port.port, port.service) else "http"
    address = host_override or host_address(port.host)
    if ":" in address and not address.startswith("["):
        address = f"[{address}]"
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{address}" if port.port == default else f"{scheme}://{address}:{port.port}"


# --- Nmap -----------------------------------------------------------------------------------------

@dataclass
class NmapResult:
    """Everything the port-scan stage needs from one Nmap XML report."""

    ports: list[PortFinding] = field(default_factory=list)
    hosts_up: int = 0  # hosts reported as up; with --open these are the hosts with an open port plus timed-out ones
    # Labels of the hosts that hit --host-timeout. Nmap writes no port table for such a host, so its findings
    # are missing altogether rather than incomplete.
    timed_out_hosts: list[str] = field(default_factory=list)
    truncated: bool = False  # the XML was cut off (Nmap was killed) and only complete hosts were kept

    @property
    def hosts_timed_out(self) -> int:
        """How many hosts hit --host-timeout."""
        return len(self.timed_out_hosts)


def parse_nmap_xml_full(xml_text: str) -> NmapResult:
    """Parse `nmap -oX -` output into open ports and host counts.

    When Nmap is killed mid-write the XML is cut off. Every complete <host> block is then kept and the
    result is marked `truncated`, so the stage can report partial results instead of failing.
    """
    result = NmapResult()
    if not xml_text.strip():
        return result
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        result.truncated = True
        root = _salvage_complete_hosts(xml_text)
        if root is None:
            return result

    for host in root.iter("host"):
        display_host = _host_label(host)
        if host.get("timedout") == "true":
            result.timed_out_hosts.append(display_host)
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            result.hosts_up += 1
        for port_el in host.iter("port"):
            finding = _open_port(port_el, display_host)
            if finding is not None:
                result.ports.append(finding)
    return result


def parse_nmap_xml(xml_text: str) -> tuple[list[PortFinding], int]:
    """Short form of parse_nmap_xml_full() that returns only (open ports, hosts up)."""
    result = parse_nmap_xml_full(xml_text)
    return result.ports, result.hosts_up


def _salvage_complete_hosts(xml_text: str) -> ET.Element | None:
    """Cut truncated XML after its last complete </host> and close the document; None if nothing is usable."""
    cut = xml_text.rfind("</host>")
    if cut == -1:
        return None
    try:
        return ET.fromstring(xml_text[: cut + len("</host>")] + "</nmaprun>")
    except ET.ParseError:
        return None


def _host_label(host: ET.Element) -> str:
    """How a host is shown: "name (address)" when Nmap resolved a hostname, else the address (IPv4 preferred)."""
    address_el = host.find("address[@addrtype='ipv4']")
    if address_el is None:
        address_el = host.find("address[@addrtype='ipv6']")
    address = address_el.get("addr") if address_el is not None else "unknown"
    hostname_el = host.find("hostnames/hostname")
    hostname = hostname_el.get("name") if hostname_el is not None else ""
    return address if not hostname else f"{hostname} ({address})"


def _open_port(port_el: ET.Element, display_host: str) -> PortFinding | None:
    """A PortFinding for an open <port> element; closed and filtered ports give None."""
    state_el = port_el.find("state")
    state = state_el.get("state", "") if state_el is not None else ""
    if state != "open":
        return None
    service_el = port_el.find("service")
    service = product = version = extra = tunnel = ""
    if service_el is not None:
        service = service_el.get("name", "")
        product = service_el.get("product", "")
        version = service_el.get("version", "")
        extra = service_el.get("extrainfo", "")
        tunnel = service_el.get("tunnel", "")
    extra = "; ".join(note for note in [extra, *_script_notes(port_el)] if note)
    port_number = int(port_el.get("portid", "0"))
    return PortFinding(
        host=display_host,
        port=port_number,
        protocol=port_el.get("protocol", "tcp"),
        state=state,
        service=f"{tunnel}/{service}" if tunnel and service else service,
        product=product,
        version=version,
        extra=extra,
        is_web=is_web_service(port_number, service, tunnel),
    )


# At most this many script results are kept per port, each cut to this many characters, so a chatty
# script (ssl-cert prints a whole certificate) cannot bloat a port's "extra" column.
MAX_SCRIPT_NOTES = 3
MAX_SCRIPT_NOTE_CHARS = 120
# Script results worth a note, most useful first. Nmap lists a port's scripts alphabetically, so without
# this ranking the http-* results of an HTTPS port would crowd out its certificate.
PREFERRED_SCRIPTS = ("ssl-cert", "ssh-hostkey", "http-title", "ftp-anon", "ftp-syst", "mysql-info",
                     "http-generator", "http-robots.txt", "smb-os-discovery", "banner")
# Script results that repeat what -sV already reported, or carry no observation of their own.
IGNORED_SCRIPTS = {"http-methods", "http-server-header", "http-favicon", "ssl-date", "tls-alpn", "tls-nextprotoneg",
                   "fingerprint-strings", "http-cors"}


def _script_notes(port_el: ET.Element) -> list[str]:
    """"script-id: output" notes for the NSE scripts Nmap ran against a port (the "scripts" profile adds -sC;
    the other profiles run none). Preferred scripts come first, then the rest in document order; each output
    is collapsed to one line and shortened with a "..." marker when it is cut."""
    candidates = []
    for position, script in enumerate(port_el.findall("script")):
        script_id = script.get("id") or ""
        output = " ".join((script.get("output") or "").split())
        if not script_id or not output or script_id in IGNORED_SCRIPTS:
            continue
        rank = PREFERRED_SCRIPTS.index(script_id) if script_id in PREFERRED_SCRIPTS else len(PREFERRED_SCRIPTS)
        candidates.append((rank, position, script_id, output))
    candidates.sort(key=lambda candidate: candidate[:2])
    return [f"{script_id}: {_shorten(output)}" for _, _, script_id, output in candidates[:MAX_SCRIPT_NOTES]]


def _shorten(text: str) -> str:
    """`text` cut to MAX_SCRIPT_NOTE_CHARS at a word boundary, ending in "..." when something was dropped, so a
    cut number, date or hash is never shown as if it were complete."""
    if len(text) <= MAX_SCRIPT_NOTE_CHARS:
        return text
    limit = MAX_SCRIPT_NOTE_CHARS - 3
    cut = text.rfind(" ", 0, limit + 1)
    if cut < limit // 2:  # no usable space: one very long token, cut it mid-way rather than drop it
        cut = limit
    return text[:cut].rstrip() + "..."


# --- WhatWeb --------------------------------------------------------------------------------------

# WhatWeb plugins that describe the connection rather than the software, so they are not technologies.
_SKIP_PLUGINS = {"IP", "Country", "RedirectLocation", "UncommonHeaders"}


def parse_whatweb_json(text: str, probed_url: str, host: str, port: int) -> WebFinding:
    """Build a WebFinding from WhatWeb's --log-json output (one JSON object per request or redirect).

    The finding keeps the URL that was probed; where WhatWeb ended up after redirects is `final_url`.
    `reachable` is False when WhatWeb produced no entry at all (connection refused, timeout, ...).
    """
    entries = _whatweb_entries(text)
    technologies: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    status_code = None
    title = None
    final_url = None
    for entry in entries:
        target = entry.get("target")
        if target:
            final_url = str(target)
        status_code = _as_int(entry.get("http_status")) or status_code
        # Tolerate shapes WhatWeb should never produce (a list instead of the plugin dict, a plugin whose
        # detail is not a dict, a scalar where a list is expected): a parser error must not fail the stage.
        plugins = entry.get("plugins")
        if not isinstance(plugins, dict):
            plugins = {}
        for name, raw_detail in plugins.items():
            detail = raw_detail if isinstance(raw_detail, dict) else {}
            if name == "Title":
                strings = _as_list(detail.get("string"))
                if strings:
                    title = str(strings[0])[:300]
                continue
            if name in _SKIP_PLUGINS:
                continue
            versions = [str(v) for v in _as_list(detail.get("version"))]
            strings = [str(s) for s in _as_list(detail.get("string"))]
            # Every redirect hop reports the same plugins again; keep the first report of each.
            key = (name, versions[0] if versions else (strings[0] if strings else ""))
            if key in seen:
                continue
            seen.add(key)
            technologies.append(_technology(name, versions, strings))
    return WebFinding(
        url=probed_url, host=host, port=port, status_code=status_code, title=title,
        technologies=technologies, reachable=bool(entries),
        final_url=final_url if final_url and final_url.rstrip("/") != probed_url.rstrip("/") else None,
    )


def _whatweb_entries(text: str) -> list[dict[str, Any]]:
    """The JSON objects in a WhatWeb log: normally one JSON array, but some versions write one object per line."""
    entries: list[Any] = []
    text = text.strip()
    if text:
        try:
            data = json.loads(text)
            entries = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for raw_line in text.splitlines():
                line = raw_line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return [entry for entry in entries if isinstance(entry, dict)]


def _as_list(value: Any) -> list[Any]:
    """WhatWeb reports versions and strings as lists; a missing value gives [] and a bare scalar is wrapped,
    so "7.4" never turns into the characters "7", ".", "4"."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _as_int(value: Any) -> int | None:
    """An int from a JSON number or numeric string; None for anything else (never a validation error)."""
    try:
        return int(value) if value is not None and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def _technology(name: str, versions: list[str], strings: list[str]) -> dict[str, Any]:
    """One technology entry: its name, plus any versions and descriptive strings WhatWeb reported."""
    tech: dict[str, Any] = {"name": name}
    if versions:
        tech["version"] = ", ".join(versions)
    if strings:
        tech["string"] = ", ".join(strings)[:200]
    return tech


# --- Nikto ----------------------------------------------------------------------------------------

# Nikto does not grade its findings, so severity is estimated from keywords. The first tier with a match
# wins, which is why the list runs from critical down to low.
_NIKTO_SEVERITY_HINTS = [
    ("critical", ("remote code", "rce", "shell", "shellshock", "sql injection", "backdoor", "command execution",
                  "remote file inclusion", "rfi")),
    ("high", ("directory indexing", "phpinfo", "phpmyadmin", "config", "configuration", ".git", "password", "admin",
              "administrator", "manager", "upload", "uploaded", "traversal", "default credentials")),
    ("medium", ("outdated", "appears to be outdated", "xss", "cross-site", "clickjacking", "x-frame-options",
                "cookie", "allowed http methods", "trace")),
    ("low", ("x-content-type-options", "content-type", "banner", "retrieved", "server leaks", "etag", "inode")),
]
_NIKTO_SEVERITY_RE = [
    # Whole words only (so "rce" never matches inside "source"), with an optional plural s ("backdoors").
    (severity, re.compile(r"(?<![a-z0-9])(?:" + "|".join(re.escape(k) for k in keywords) + r")s?(?![a-z0-9])",
                          re.IGNORECASE))
    for severity, keywords in _NIKTO_SEVERITY_HINTS
]
# Lines of Nikto's text output that are banners or statistics rather than findings. The header Nikto prints before
# it runs a test describes the target and the scan ("Target IP:", "SSL Info:" for an HTTPS port, "Virtual Host:",
# "Platform:", "Using Encoding:" and "Using Mutation:" for -evasion and -mutate, "Proxy:"); none of it is a finding.
_NIKTO_NOISE_PREFIXES = ("Target ", "Start Time", "End Time", "Server:", "No CGI Directories", "Nikto v",
                         "ERROR:", "Scan terminated", "Multiple IPs", "No web server found", "SSL Info:",
                         "Virtual Host:", "Platform:", "Using Encoding:", "Using Mutation:", "Proxy:")
# Status lines that show Nikto stopped before it examined a URL completely: it gave up after too many errors
# ("ERROR: Error limit (20) reached for host, giving up"), reached its -maxtime ("ERROR: Host maximum
# execution time of 45 seconds reached"), found no web server on the port, or tested no host at all.
_NIKTO_STOPPED_PREFIXES = ("ERROR:", "Scan terminated", "0 host(s) tested", "No web server found")
_NIKTO_NOISE_RE = re.compile(r"^\d+ (host\(s\) tested|requests:|items? checked)")


def classify_nikto(message: str) -> str:
    """Estimate the severity of a Nikto message: critical, high, medium, low, or info when nothing matches.

    Keywords match whole words only (an optional plural "s" is allowed), so "rce" never matches inside "source"
    or "force" while "backdoors" still counts.
    """
    for severity, pattern in _NIKTO_SEVERITY_RE:
        if pattern.search(message):
            return severity
    return "info"


def nikto_output_is_json(text: str) -> bool:
    """True when Nikto's -output file holds JSON. Otherwise the pipeline parses the text Nikto printed."""
    return _nikto_json_data(text) is not None


def _nikto_json_data(text: str) -> Any:
    """The parsed JSON of a Nikto report, or None when the text is not JSON.

    Nikto's JSON writer is known to emit a bare sequence of host objects ("{...},{...}") or a trailing comma
    instead of one array, so those forms are wrapped in brackets before giving up.
    """
    text = text.strip()
    if not text:
        return None
    for candidate in (text, "[" + text.rstrip(",") + "]"):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


# A Nikto "url" value is a full URL only when it starts with a scheme. "://" later in the value (Nikto's RFI
# tests send ?page=http://cirt.net/rfiinc.txt?) belongs to a path on the scanned service.
_ABSOLUTE_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def _finding_url(base_url: str, path: Any) -> str:
    """Join Nikto's "url" field (normally a path such as /manager/html) onto the scanned URL.

    A full URL (one that starts with a scheme such as http://) is kept as it is, and a path without a leading
    slash gets one, so the result is always a well-formed URL (compare.py splits it; "http://hostmanager/html"
    would not be).
    """
    if path is None or path == "":
        return base_url
    path = str(path)
    if _ABSOLUTE_URL_RE.match(path):
        return path
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def parse_nikto_json(text: str, url: str) -> list[VulnFinding]:
    """Findings from Nikto's JSON report: a list of hosts, each with a "vulnerabilities" list.

    Paths in the report are appended to `url`. Text that is not JSON is passed to parse_nikto_text().
    Entries that are not the dictionaries Nikto writes are skipped rather than failing the stage.
    """
    findings: list[VulnFinding] = []
    text = text.strip()
    if not text:
        return findings
    data = _nikto_json_data(text)
    if data is None:
        return parse_nikto_text(text, url)
    hosts = data if isinstance(data, list) else [data]
    for host in hosts:
        if not isinstance(host, dict):
            continue
        vulns = host.get("vulnerabilities")
        for vuln in (vulns if isinstance(vulns, list) else []):
            if not isinstance(vuln, dict):
                continue
            message = str(vuln.get("msg") or "").strip()
            if not message:
                continue
            findings.append(
                VulnFinding(
                    url=_finding_url(url, vuln.get("url")),
                    severity=classify_nikto(message),
                    description=message,
                    reference=str(vuln.get("references") or vuln.get("id") or ""),
                )
            )
    return findings


def parse_nikto_text(text: str, url: str) -> list[VulnFinding]:
    """Fallback for Nikto's human-readable output: every "+ " line that is not a banner or a statistic."""
    findings = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("+ "):
            continue
        message = line[2:].strip()
        if message.startswith(_NIKTO_NOISE_PREFIXES) or _NIKTO_NOISE_RE.match(message) or "requests:" in message:
            continue
        findings.append(VulnFinding(url=url, severity=classify_nikto(message), description=message))
    return findings


def nikto_stopped_early(text: str) -> str | None:
    """The first status line in Nikto's printed output that shows it stopped before it examined the URL
    completely (an ERROR line, "Scan terminated", "0 host(s) tested", "No web server found"), or None.

    Nikto prints these lines even when it also writes its JSON report, so the pipeline asks for every URL,
    whichever form the findings came in: such a URL is never recorded as completely examined."""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("+ ") and line[2:].strip().startswith(_NIKTO_STOPPED_PREFIXES):
            return line[2:].strip()[:120]
    return None


def nikto_reached_maxtime(text: str) -> bool:
    """True when Nikto stopped because it reached its own -maxtime ("ERROR: Host maximum execution time of 45
    seconds reached"): it ran its tests for the whole time slice, so the URL was examined, not completely."""
    return "maximum execution time" in text


def nikto_text_problem(text: str) -> str | None:
    """Why Nikto's text output shows that it never examined the target, or None when it did.

    An error line ("ERROR: Cannot resolve hostname", "ERROR: Error limit (20) reached for host, giving up"),
    a "Scan terminated", "0 host(s) tested" or "No web server found" line means the URL was not checked, and
    so does output without a single "+ " line (the banner alone).
    """
    stopped = nikto_stopped_early(text)
    if stopped is not None:
        return stopped
    if not any(line.strip().startswith("+ ") for line in text.splitlines()):
        return "no scan output (banner only)"
    return None
