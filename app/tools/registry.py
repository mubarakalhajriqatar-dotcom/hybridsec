"""Catalogue of the external tools HybridSec can chain, and detection of which ones are installed.

Each ToolSpec says how to find the tool's executable, which pipeline stage it serves, how to install it
and which profiles (preset flag sets) the operator may pick for it on the New Run form. The rest of the
application only ever refers to tools by the keys of TOOLS and to profiles by their keys, so supporting a
new tool or a new profile starts here (see docs/ARCHITECTURE.md, "How to extend with a new tool"). Tools the
operator registers without a code change (the Custom tools page) are defined in custom.py instead; they have no
parser and no profiles, and run after these.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Collection
from dataclasses import dataclass
from functools import cache

from ..schemas import ToolInfo, ToolProfileInfo


@dataclass(frozen=True)
class ToolProfile:
    """One way of using a tool, chosen per run from a drop-down on the New Run form (Zenmap calls these
    "profiles" too).

    `args` are the arguments the profile contributes to the tool's command line. The pipeline adds the
    fixed parts itself (the target, the port count, the time limits and the output format), so a profile
    decides how a tool examines the target, never what it examines. Only non-exploitative options belong here;
    some (Nikto's default and injection, WhatWeb level 4, Nmap's scripts) are intrusive: authorised targets only.
    """

    key: str
    label: str
    description: str
    args: tuple[str, ...]

    @property
    def flags(self) -> str:
        """The profile's arguments as one string, for the dashboard and the reports ("" for none)."""
        return " ".join(self.args)


@dataclass(frozen=True)
class ToolSpec:
    """Static facts about one external tool.

    `binaries` lists executable names to look for on PATH, in order of preference. `version_args` and
    `version_regex` describe how to ask the tool for its version and where to find it in the output.
    `profiles` are the flag sets the operator may choose from; the first one is the default and is what
    the pipeline used before profiles existed.
    """

    name: str
    display_name: str
    category: str
    description: str
    stage: str
    binaries: tuple[str, ...]
    version_args: tuple[str, ...]
    version_regex: str
    install_hint: str
    profiles: tuple[ToolProfile, ...]


TOOLS: dict[str, ToolSpec] = {
    "nmap": ToolSpec(
        name="nmap",
        display_name="Nmap",
        category="Network discovery",
        description="Discovers live hosts, open TCP ports and the services/versions behind them.",
        stage="port_scan",
        binaries=("nmap",),
        version_args=("--version",),
        version_regex=r"Nmap version ([\d.]+)",
        install_hint="Ubuntu/Kali: sudo apt install nmap  |  Windows: https://nmap.org/download.html",
        # Every Nmap profile keeps -Pn (no ping, so a host that drops ping probes is still scanned); the
        # pipeline appends --open, --top-ports, --host-timeout and the XML output option.
        profiles=(
            ToolProfile("version", "Service and version detection",
                        "Probes each open port for the service, product and version behind it (-sV). "
                        "The standard HybridSec scan.", ("-sV", "-Pn", "-T4")),
            ToolProfile("quick", "Quick port scan",
                        "Reports open ports with Nmap's service names only, without version probes. "
                        "The fastest profile; the web stages still run on the HTTP ports it finds.",
                        ("-Pn", "-T4")),
            ToolProfile("scripts", "Version detection + default scripts",
                        "Adds Nmap's default script set (-sC): page titles, TLS certificate details, SSH host "
                        "keys and similar details are recorded per port. Sends more probes than the "
                        "standard scan.", ("-sV", "-sC", "-Pn", "-T4")),
            ToolProfile("polite", "Version detection, polite timing",
                        "The standard scan at Nmap's polite timing (-T2): probes are sent one at a time with "
                        "0.4 s between them, for fragile lab devices. Several times slower, so give the run "
                        "a longer time budget.", ("-sV", "-Pn", "-T2")),
        ),
    ),
    "whatweb": ToolSpec(
        name="whatweb",
        display_name="WhatWeb",
        category="Web fingerprinting",
        description="Identifies web servers, frameworks, CMS platforms, JavaScript libraries and versions.",
        stage="web_fingerprint",
        binaries=("whatweb",),
        version_args=("--version",),
        version_regex=r"WhatWeb version ([\d.]+[\w-]*)",
        install_hint="Ubuntu/Kali: sudo apt install whatweb  |  Windows: run inside WSL (Ubuntu).",
        # WhatWeb's aggression levels (level 2 is unused by WhatWeb itself). Redirects stay same-site at
        # every level.
        profiles=(
            ToolProfile("stealthy", "Stealthy, level 1",
                        "One HTTP request per URL, plus same-site redirects. Technologies and versions come "
                        "from that single response.", ("-a", "1")),
            ToolProfile("aggressive", "Aggressive, level 3",
                        "When a plugin matches, WhatWeb sends that plugin's extra requests to confirm the "
                        "product and pin down its version.", ("-a", "3")),
            ToolProfile("heavy", "Heavy, level 4",
                        "Every plugin's extra requests are tried on every URL: the most complete fingerprint, "
                        "at the cost of many requests per URL.", ("-a", "4")),
        ),
    ),
    "nikto": ToolSpec(
        name="nikto",
        display_name="Nikto",
        category="Web vulnerability scanning",
        description="Checks web servers for dangerous files, outdated software and common misconfigurations.",
        stage="web_vuln_scan",
        binaries=("nikto", "nikto.pl"),
        version_args=("-Version",),
        version_regex=r"Nikto\s+v?([\d.]+)",
        install_hint="Ubuntu/Kali: sudo apt install nikto  |  Windows: run inside WSL (Ubuntu).",
        # Nikto's -Tuning selects test categories by their letters (1 interesting files, 2 misconfiguration
        # and default files, 3 information disclosure, 4 XSS/script injection, 9 SQL injection, b software
        # identification, c remote source inclusion, e administrative consoles).
        profiles=(
            ToolProfile("all", "All checks",
                        "Nikto's own default selection of tests: the complete scan.", ()),
            ToolProfile("files", "Files and misconfiguration",
                        "Interesting and default files, misconfigurations and information disclosure "
                        "(-Tuning 123). Quicker than the complete scan.", ("-Tuning", "123")),
            ToolProfile("software", "Software and admin consoles",
                        "Software identification, outdated components and reachable administrative "
                        "consoles (-Tuning be).", ("-Tuning", "be")),
            ToolProfile("injection", "Injection checks",
                        "Cross-site scripting, SQL injection and remote source inclusion probes "
                        "(-Tuning 49c). Intrusive test strings, nothing exploited: authorised targets only.",
                        ("-Tuning", "49c")),
        ),
    ),
}

# Execution order of the pipeline stages. dns_lookup is reserved for a future DNS tool; none ships yet.
STAGE_ORDER = ["dns_lookup", "port_scan", "web_fingerprint", "web_vuln_scan"]

# The workflow used when a request names no tools: the original Nmap + WhatWeb hybrid.
DEFAULT_TOOLS = ("nmap", "whatweb")


# --- Installation status --------------------------------------------------------------------------

def resolve_binary(spec: ToolSpec) -> str | None:
    """Full path of the first of the tool's executables found on PATH, or None when it is not installed.

    This is looked up on every call (it is cheap), so a tool installed while the server runs is noticed.
    """
    for binary in spec.binaries:
        path = shutil.which(binary)
        if path:
            return path
    return None


@cache
def detect_version(path: str, args: tuple[str, ...], regex: str) -> str | None:
    """Ask an executable for its version. Cached per executable, because starting a scanner takes a moment."""
    try:
        proc = subprocess.run(
            # check=False: some tools exit non-zero after printing their banner, which is all we need.
            [path, *args], capture_output=True, text=True, timeout=15, errors="replace", check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (proc.stdout or "") + (proc.stderr or "")
    match = re.search(regex, output)
    return match.group(1) if match else None


def tool_info(name: str) -> ToolInfo:
    """The API view of one tool, including whether and where it is installed."""
    spec = TOOLS[name]
    path = resolve_binary(spec)
    version = detect_version(path, spec.version_args, spec.version_regex) if path else None
    return ToolInfo(
        name=spec.name,
        display_name=spec.display_name,
        category=spec.category,
        description=spec.description,
        stage=spec.stage,
        installed=path is not None,
        path=path,
        version=version,
        install_hint=spec.install_hint,
        profiles=[ToolProfileInfo(key=p.key, label=p.label, description=p.description, flags=p.flags,
                                  default=index == 0) for index, p in enumerate(spec.profiles)],
    )


def list_tools() -> list[ToolInfo]:
    """Every supported tool, in catalogue order."""
    return [tool_info(name) for name in TOOLS]


def availability() -> dict[str, bool]:
    """Tool name to installed yes/no, without the slower version check."""
    return {name: resolve_binary(spec) is not None for name, spec in TOOLS.items()}


# --- Tool names -----------------------------------------------------------------------------------

def known_tool(name: str) -> bool:
    """True when `name` (any letter case, surrounding spaces ignored) is a supported tool.

    Spaces are ignored because order_tools() ignores them too; otherwise " nmap" would be rejected as
    unknown by one function and accepted by the other.
    """
    return name.strip().lower() in TOOLS


def unknown_tools(names: list[str], custom: Collection[str] = ()) -> list[str]:
    """The entries of `names` that are neither supported tools nor in `custom` (the registered custom tool names,
    see custom.py), in their original spelling."""
    return [name for name in names if not known_tool(name) and name.strip().lower() not in custom]


def describe_unknown_tools(names: list[str], limit: int = 5) -> str:
    """The unknown tool names for an error message: each cut to 80 characters, a repeated name once, and at
    most `limit` of them followed by a count of the rest, so a huge request never produces a huge answer."""
    unique = list(dict.fromkeys(name[:80] for name in names))
    shown = ", ".join(unique[:limit])
    return shown + (f" and {len(unique) - limit} more" if len(unique) > limit else "")


def order_tools(names: list[str], custom: Collection[str] = ()) -> list[str]:
    """Return the known tools from `names`, de-duplicated and sorted into pipeline stage order, followed by the
    names in `custom` (registered custom tools) in alphabetical order.

    The caller's order is ignored on purpose: each stage consumes the previous stage's output, so
    nmap must run before whatweb, and whatweb before nikto. Custom tools run last, on what those found.
    """
    seen: list[str] = []
    for name in names:
        key = name.lower().strip()
        if (key in TOOLS or key in custom) and key not in seen:
            seen.append(key)
    return sorted(seen, key=lambda n: (STAGE_ORDER.index(TOOLS[n].stage), "") if n in TOOLS
                  else (len(STAGE_ORDER), n))


# --- Profiles -------------------------------------------------------------------------------------

def default_profile(tool: str) -> ToolProfile:
    """The profile a run uses for `tool` when its request names none: the first in the catalogue."""
    return TOOLS[tool].profiles[0]


def find_profile(tool: str, key: str | None) -> ToolProfile | None:
    """The profile of `tool` called `key` (any letter case, surrounding spaces ignored), or None when the
    tool offers no such profile. A missing or blank key means the default."""
    if key is None or not key.strip():
        return default_profile(tool)
    wanted = key.strip().lower()
    return next((profile for profile in TOOLS[tool].profiles if profile.key == wanted), None)


def profile_for_run(tool: str, chosen: dict[str, str] | None) -> ToolProfile:
    """The profile the pipeline applies for `tool` in a run whose recorded choices are `chosen` (Run.profiles).

    An unknown key falls back to the default, so a run saved before profiles existed, or one whose profile
    was later renamed, still executes and still renders.
    """
    return find_profile(tool, (chosen or {}).get(tool)) or default_profile(tool)


def profile_label(tool: str, key: str | None) -> str:
    """The human-readable name of a profile, for the reports and the comparison; the key itself when it is
    not in the catalogue."""
    profile = find_profile(tool, key) if tool in TOOLS else None
    return profile.label if profile else (key or "")
