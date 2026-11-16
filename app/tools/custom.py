"""Custom tools: extra command-line tools the operator registers on the dashboard's Custom tools page.

A custom tool is a stored definition: a name, a program, an argument list in which only {target} and {url} are
filled in, whether it runs once on the run's target or once per web URL, and a time limit per call. It runs after
the built-in stages (hybrid.stage_custom_tool) through the same runner as the scanners: an argument list, no shell,
stdin closed, the process tree killed at its time limit, and at most STDOUT_CHARS of output read. Its output is
kept as text and is never parsed into findings or scored.

Registering, listing and running custom tools is only possible from the machine running HybridSec (see
routers/tools.py and routers/hybrid.py). The rules in this module keep the safety story of the built-in tools true:
- the program must be on the allow-list (HYBRIDSEC_CUSTOM_PROGRAMS in .env, by default a few information-gathering
  programs). An entry written as a path allows only that file (a relative path is read from the folder HybridSec
  was started from); an entry written as a name allows that name from any folder. Shells, interpreters, launchers,
  remote shells, database and code consoles, script files, attack tools and the built-in scanners are refused
  whatever the list says, by their name and by the name of the file they resolve to;
- the file that is checked is the file that runs (symbolic links are followed). It may not be a script, a special
  system file, a file on a network share, or a file inside HybridSec's own folder (the one that holds app/, .venv
  included);
- every argument is one token without quotes, and only {target} and {url} point the tool at a host, so the run's
  target validation and authorisation apply to them. With the placeholders removed (full-width characters read as
  their plain forms), an argument is refused when it contains a URL (://); an IPv4 address written as four dotted
  numbers anywhere (also with a port, or after = , @ or :); an IPv6 address (in brackets, with ::, or written out in
  full); an @ (dig @server, user@host, {url}@host, curl -d @file and other @file option files; only dig @{target} is
  allowed); two slashes or backslashes where a path starts (at the start of the argument, after = , : @ or < as in
  curl's -F name=<file, or right after a short option's letters as in -T//srv/share), two backslashes anywhere, or
  the NT prefix \\??\\, which Windows reads as a network path (\\\\server\\share, //server/share, /\\server,
  \\??\\UNC\\server); curl's [ ] ranges, which reach many hosts in one call; or a
  piece between = , : and @ that looks like a host name: localhost, or a dotted name whose last label is letters,
  such as dns.example or dns.example:53 (also when a path, a ? query or a # fragment follows, and after the one
  slash of a URL such as http:/dns.example). The URL, address and host-name tests also decode %-escapes, as the
  tools do in a host name (%31%30.0.0.1, %65vil.example); the [ ], @ and two-slash tests read the text as written,
  because curl sends %5B, %40 and %2F in a path or query as they are. The host-name rule also refuses a bare file
  name such as out.txt, which can be written ./out.txt instead. {target}:443 (a placeholder with a port) and two
  slashes inside a path ({url}/a//b) are allowed;
- options that send the traffic somewhere else or read more options or targets from a file are refused, also
  bundled (-sK) or abbreviated (--conf): curl's -K/--config, -x/--proxy, --preproxy, --proxy1.0, --socks4,
  --socks4a, --socks5, --socks5-hostname, --connect-to, --resolve, --doh-url, --dns-servers, --unix-socket,
  --abstract-unix-socket, --alt-svc and -:/--next; whois -h/--host; dig -f; sslyze --targets_in and --https_tunnel;
  sslscan --targets; traceroute -g/--gateway and tracert -j;
- exploit wording, options that pass credentials (curl -u, -b, -E and the like) and values that look like
  passwords or keys are refused.
Every other option the operator types is trusted: the rules cannot know what each option of each program does (curl
-L follows redirects the target sends, -o writes a file, a single-word host name such as intranet is not
recognised, nor is an IPv4 address in a short or numeric form such as 127.1, 2130706433 or 0x7f000001), so only the
forms above are refused. A copied and renamed program cannot be recognised by its name either: the allow-list is the
real gate.

The module imports no configuration or storage (scripts/preflight.py relies on that): settings are passed in.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import unicodedata
import urllib.parse
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType

from ..schemas import CustomTool, CustomToolCreate, CustomToolInfo
from .registry import TOOLS

CUSTOM_STAGE = "custom_tool"  # StageResult.stage of a custom tool; not in STAGE_ORDER, custom tools run last
MAX_CUSTOM_TOOLS = 10
STDOUT_CHARS = 50_000  # per call; a tool that prints more is stopped
STDERR_CHARS = 5_000  # per call
RUN_OUTPUT_CHARS = 200_000  # per run, across all custom tools (every poll copies the whole run)

# The programs the Custom tools page accepts when HYBRIDSEC_CUSTOM_PROGRAMS is empty: tools that only gather
# information about a host or a web URL.
DEFAULT_PROGRAMS = ("curl", "dig", "host", "nslookup", "whois", "sslscan", "sslyze", "traceroute", "tracert")

# Files that need an interpreter, or cmd.exe on Windows (which runs .bat and .cmd files through a shell even when
# HybridSec does not use one).
SCRIPT_SUFFIXES = (".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".msc",
                   ".scr", ".lnk", ".sh", ".bash", ".zsh", ".ksh", ".py", ".pyw", ".pl", ".rb", ".php", ".lua", ".tcl",
                   ".jar")

# Programs that run their arguments as commands: shells, interpreters, launchers, debuggers, package runners, remote
# shells, file-transfer and database consoles (which run batch files, local commands or queries), code runners and
# editors. Names are compared without a trailing version (see _program_key), so sqlite stands for sqlite3,
# proxychains for proxychains4, linux for linux32 and linux64 (setarch), r for R and R.exe, and m for m4.
_SHELL_NAMES = """
    sh bash rbash dash ash zsh ksh mksh yash csh tcsh fish busybox env xargs find awk gawk mawk nawk sed nohup nice
    setsid timeout watch script sudo doas su runas pkexec chroot nsenter unshare strace ltrace gdb vi vim ex view nano
    git tar cmd command conhost powershell pwsh wsl forfiles pcalua cscript wscript mshta rundll regsvr msiexec
    schtasks at python pythonw py pypy ipython perl ruby irb node nodejs js deno bun php lua luajit tclsh wish expect
    java javaw osascript make ssh scp nc ncat netcat socat telnet ubuntu debian kali opensuse sles alpine fedora
    pyw wmic wt explorer bitsadmin certutil msbuild installutil cmstp hh dotnet time stdbuf flock taskset ionice
    chrt systemd-run run-parts screen tmux xterm docker podman kubectl rsync zip toybox
    pwsh-preview powershell_ise nvim emacs jshell jrunscript rscript rterm julia php-cgi sqlite lldb cdb valgrind
    winrs psexec plink sc setarch linux prlimit runuser proxychains torsocks dotenv aria2c regasm msxsl odbcconf
    mavinject scriptrunner tttracer mintty git-bash scapy npm npx pnpm yarn pip pipx uv uvx poetry conda cargo go
    uvicorn watchfiles fastapi flask gunicorn hypercorn pytest coverage
    r ntsd sftp ftp regsvcs psql mysql mongosh mongo sqlcmd sqlplus groovy scala kotlin jython elixir erl iex ghci
    runghc racket guile sbcl octave gnuplot ts-node tsx gsudo msdt ieexec mmc
    parallel ssh-agent capsh unbuffer gmake nmake cmake csi dotnet-script clisp ocaml swipl maxima
    gp sage matlab xdg-open open start cygstart wslview smbclient lftp autossh mosh rlwrap firejail bwrap wine mono
    tcc jjs less ed dc m
"""
SHELLS = frozenset(_SHELL_NAMES.split())

# Exploitation, password-guessing, brute-force, fuzzing, load-testing and wireless-attack tools: HybridSec is
# non-exploitative.
_ATTACK_NAMES = """
    msfconsole msfvenom msfrpcd msfdb armitage sqlmap commix xsser hydra medusa ncrack patator crowbar john hashcat
    crackmapexec netexec nxc responder ettercap bettercap hping slowhttptest slowloris searchsploit setoolkit
    routersploit wfuzz ffuf gobuster dirb dirbuster feroxbuster nuclei wpscan kerbrute evil-winrm dalfox xsstrike
    masscan zmap siege ab wrk thc-ssl-dos impacket-psexec impacket-secretsdump wapiti fierce aircrack-ng
    aireplay-ng reaver wifite arpspoof mdk
"""
ATTACK_TOOLS = frozenset(_ATTACK_NAMES.split())

REFUSED_WORDS = ("brute", "exploit", "fuzz", "attack")  # the same words the built-in profiles may not use
SECRET_WORDS = ("password", "passwd", "secret", "token", "apikey", "api-key", "api_key", "bearer", "cookie",
                "authorization", "credential")
# Options whose value is a credential (curl's long names; other tools use the same names where they have them).
CREDENTIAL_OPTIONS = frozenset({"--user", "--proxy-user", "--pass", "--proxy-pass", "--pkpass", "--cert",
                                "--proxy-cert", "--tlsuser", "--proxy-tlsuser", "--cookie", "--oauth2-bearer"})
# curl's short options that take a value, and those whose value is a credential (-u/--user, -U/--proxy-user,
# -b/--cookie, -E/--cert). curl lets short options be bundled (-su admin:pw), so the whole word is read.
_CURL_VALUE_LETTERS = frozenset("AbcCdDeEFHKmoPQrtTuUwxXyYz")
_CURL_CREDENTIAL_LETTERS = frozenset("uUbE")

# Options that send the tool's traffic somewhere other than {target} or {url}, or read more options or targets from a
# file, per program: (long names, short letters). An abbreviation of a long name is refused too (curl, whois and
# sslyze accept a unique prefix), and the short letters are found in a bundle such as -sK. _VALUE_LETTERS are each
# program's short options that take a value: the rest of a word after one of them is that value, not more options.
_ROUTING_OPTIONS = {
    "curl": (("--config", "--proxy", "--preproxy", "--proxy1.0", "--socks4", "--socks4a", "--socks5",
              "--socks5-hostname", "--connect-to", "--resolve", "--doh-url", "--dns-servers", "--unix-socket",
              "--abstract-unix-socket", "--alt-svc", "--next"), "Kx:"),
    "whois": (("--host",), "h"),
    "dig": ((), "f"),
    "sslyze": (("--targets_in", "--https_tunnel"), ""),
    "sslscan": (("--targets",), ""),
    "traceroute": (("--gateway",), "g"),
    "tracert": (("/j",), "j"),
}
_VALUE_LETTERS = {"curl": "".join(sorted(_CURL_VALUE_LETTERS)), "whois": "ghipqstTvV", "dig": "bcfkpqtxy",
                  "traceroute": "fgilmMNOpPqstwz"}

# HybridSec's own folder, the one that holds app/ (its .venv included): nothing in it may run as a custom tool,
# because the programs there (the venv's python, dotenv, uvicorn) run whatever they are given.
_BASE_DIR = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_BARE_PROGRAM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_WINDOWS_ABSOLUTE_RE = re.compile(r"[A-Za-z]:[\\/][^:]*")  # C:\... only: no network shares or device paths
_PLACEHOLDER_RE = re.compile(r"\{(target|url)\}")
_KEY_LIKE_RE = re.compile(r"[A-Za-z0-9_+/=-]{32,}")
_IPV4_RE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")  # anywhere in an argument: 10.0.0.1:80, -g10.0.0.1
_NT_PREFIX_RE = re.compile(r"[\\/]\?\?[\\/]")  # \??\UNC\server: Windows' NT prefix, passed through unchanged
_IPV6_RE = re.compile(r"::|\[[^\]]*:[^\]]*\]")  # a :: anywhere, or an address in brackets such as [fe80:0:0:0:0:0:0:1]
# dns.example, a.b.example: the last label is letters, or punycode for a non-Latin one (xn--p1ai)
_HOST_NAME_RE = re.compile(r"(?:\w[\w-]*\.)+(?:[^\W\d_]+|xn--[\w-]+)")
_ANSI_RE = re.compile(r"(?:\x1b\[|\x9b)[0-9;?]*[ -/]*[@-~]")  # colour and cursor codes (7- and 8-bit CSI)
# Terminal control strings, removed with what they carry (a window title, a hyperlink, a DCS payload): OSC, DCS and
# the rarer SOS, PM and APC, in their 7-bit (ESC ] ...) and 8-bit forms, up to their end (BEL, ESC \ or the 8-bit
# ST). One that is not ended is removed up to the end of its line, or up to an ESC, which starts the next code.
# The payload is one character class followed by an optional end, so no input (a target controls it) makes the scan
# go back: text full of introducers is still cleaned in linear time.
_CONTROL_STRING_RE = re.compile(r"(?:\x1b[\]PX^_]|[\x90\x98\x9d\x9e\x9f])[^\x07\x1b\x9c\n]*(?:\x07|\x1b\\|\x9c)?")
# C0, DEL and C1 controls except tab and newline, and the invisible format characters that could hide text or make it
# display in another order than it was printed: the bidi controls and marks, the zero-width space, the word joiner
# and invisible operators (U+2060-U+2064), the Mongolian vowel separator, the byte order mark and the tag characters
# (U+E0000-U+E007F). The zero-width non-joiner and joiner (U+200C, U+200D) stay: Persian and Indic words and emoji
# sequences need them.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u180e\u200b\u200e\u200f\u202a-\u202e\u2060-\u2064"
                         r"\u2066-\u2069\ufeff\U000e0000-\U000e007f]")


class CustomToolError(ValueError):
    """A definition breaks one of the rules; the message says which, in words for the operator."""


class AllowedPrograms(frozenset):
    """The allow-list as the rules compare it: a set of program keys (see _program_key). `shown` keeps the entries
    as they are written in .env (or the defaults), without those program_problem() always refuses: the Custom
    tools page and the "not on the list" message show those. `paths` maps a key whose entries are all written as
    paths to those entries: only those files may be registered for it."""

    shown: tuple[str, ...] = ()
    paths: Mapping[str, tuple[str, ...]] = MappingProxyType({})


# --- Rules ----------------------------------------------------------------------------------------

def allowed_programs(configured: list[str]) -> AllowedPrograms:
    """The programs the server accepts: HYBRIDSEC_CUSTOM_PROGRAMS, or DEFAULT_PROGRAMS when it is empty, as the
    keys the rules compare, with the entries as written (minus the always refused ones) in `shown`. An entry
    written as a path (C:\\Tools\\curl.exe) allows only that file, unless the same program is also listed by its
    name alone (curl), which allows it from any folder. A relative path (tools\\curl.exe) is read from the folder
    HybridSec was started from, as the runner would read it, so its full path is shown and must be registered."""
    names = [_entry(name.strip()) for name in configured if name.strip()] or list(DEFAULT_PROGRAMS)
    allowed = AllowedPrograms(_program_key(name) for name in names)
    allowed.shown = tuple(dict.fromkeys(name for name in names if program_problem(name) is None))
    by_name = {_program_key(name) for name in names if not _is_path_entry(name)}
    paths: dict[str, tuple[str, ...]] = {}
    for name in dict.fromkeys(names):
        key = _program_key(name)
        if _is_path_entry(name) and key not in by_name:
            paths[key] = (*paths.get(key, ()), name)
    allowed.paths = MappingProxyType(paths)
    return allowed


def allowed_program_names(configured: list[str]) -> list[str]:
    """The allow-list as the Custom tools page shows it: the entries as written (or the defaults), without those
    program_problem() always refuses, sorted."""
    return _shown_names(allowed_programs(configured))


def validate_definition(body: CustomToolCreate, allowed: frozenset[str], created_at: datetime,
                        look_up: bool = True) -> CustomTool:
    """Check a definition against every rule and return it normalised, or raise CustomToolError.

    `look_up` also checks the file the program resolves to (at registration). A program that is not installed
    is accepted: simulation mode runs without it, and the Custom tools page says it is missing.
    """
    name = _check_name(body.name)
    description = " ".join(body.description.split())
    if description and not description.isprintable():
        raise CustomToolError("Description: remove invisible or control characters (for example a zero-width joiner); "
                              "line breaks are joined into one line.")
    program = _check_program(body.program, allowed, look_up)
    args = _check_args(body.args, body.scope, _program_key(program))
    return CustomTool(name=name, description=description, program=program, args=args, scope=body.scope,
                      timeout_seconds=body.timeout_seconds, created_at=created_at)


def definition_problem(tool: CustomTool, allowed: frozenset[str]) -> str | None:
    """Why a stored definition no longer passes the rules (the allow-list was shortened, a rule was tightened, the
    row was edited by hand), or None when it still passes."""
    try:
        checked = validate_definition(tool, allowed, tool.created_at, look_up=False)
    except CustomToolError as exc:
        return str(exc)
    if checked.name != tool.name:  # a hand-edited row: runs and the API look tools up by the stored form
        return f"Name: {_cut(tool.name)} is not written the way registration stores names (lower case, no spaces)."
    return None


def program_problem(program: str) -> str | None:
    """Why the program, judged by its file name, may never be a custom tool (whatever the allow-list says)."""
    base = _base_name(program)
    suffix = os.path.splitext(base)[1]
    if suffix in SCRIPT_SUFFIXES:
        return (f"Program: {_cut(base)} is a script file ({suffix}), which needs an interpreter or cmd.exe to run. "
                "Register a program that runs by itself.")
    key = _program_key(program)
    if key in TOOLS:
        return f"Program: {_cut(base)} is built in. Use it through its profiles on New Run."
    # Loaders and user-mode emulators (ld-linux-x86-64.so.2, qemu-x86_64) run any program they are given.
    if key in SHELLS or key.startswith(("ld-linux", "ld.so", "ld64.so", "ld-musl", "qemu")):
        return (f"Program: {_cut(base)} is a shell, interpreter or launcher, which would run its arguments as "
                "commands. Register the tool itself, for example sslscan.")
    if key in ATTACK_TOOLS:
        return (f"Program: {_cut(base)} is an exploitation, password-guessing, brute-force or load-testing tool, "
                "which HybridSec does not run.")
    return None


def find_program(program: str) -> tuple[str | None, str | None]:
    """(path, problem) for the file `program` runs. (None, None) when it is not installed.

    The real path (symbolic links followed) is returned and is what runs, so the file that was checked is the
    file that executes: a link such as /usr/local/bin/scan -> /bin/bash is refused, and so is any file inside
    HybridSec's own folder.
    """
    path = shutil.which(program)
    if path is None:
        return None, None
    real = os.path.realpath(path)
    if real.startswith(("/proc/", "/dev/")):
        return None, f"Program: {_cut_path(program)} resolves to {_cut_path(real)}, which is a special system file. " \
                     "Register the real executable."
    if os.name == "nt":
        # A mapped network drive or a PATH entry on a share resolves to a UNC path: run nothing from a share.
        if real.startswith("\\\\") and not re.match(r"\\\\\?\\[A-Za-z]:\\", real):
            return None, (f"Program: {_cut_path(program)} resolves to {_cut_path(real)}, which is on a network share. "
                          "Register a program on a local drive.")
        if not real.lower().endswith((".exe", ".com")):
            return None, (f"Program: {_cut_path(real)} is not an .exe or .com file, so Windows would need another "
                          "program to run it.")
        # Windows looks in the current folder before PATH, so a bare name could pick up a file placed there.
        if not _is_absolute(program) and not _inside(real, _BASE_DIR) and \
                os.path.normcase(os.path.dirname(real)) == os.path.normcase(os.getcwd()):
            return None, (f"Program: {_cut_path(program)} was found in the folder HybridSec was started from "
                          f"({_cut_path(os.getcwd())}), not on PATH. Register its full path if that is intended.")
    problem = program_problem(real)
    if problem:
        return None, f"Program: {_cut_path(program)} resolves to {_cut_path(real)}. " + \
            problem.removeprefix("Program: ")
    if _inside(real, _BASE_DIR):
        return None, (f"Program: {_cut_path(program)} resolves to {_cut_path(real)}, which is inside HybridSec's own "
                      "folder (its .venv included). Register a program installed outside it.")
    return real, None


def tool_info(tool: CustomTool, allowed: frozenset[str], simulation_allowed: bool) -> CustomToolInfo:
    """The Custom tools page's view of a definition: can it run here, and if not, why. Starts no program."""
    problem = definition_problem(tool, allowed)
    refused = problem is not None  # it cannot be part of any run, simulated or live, until registered again
    path = None
    blocked = False
    if problem is None:
        path, problem = find_program(tool.program)
        blocked = problem is not None  # found, but the file it resolves to may not run
    if problem:
        hint = problem
    elif path is None:
        hint = f"{_cut_path(tool.program)} was not found on this machine. Install it, or register its full path."
        if simulation_allowed:
            hint += " Simulation mode works without it."
    else:
        hint = ""
    return CustomToolInfo(**tool.model_dump(), installed=path is not None, path=path, install_hint=hint,
                          refused=refused, blocked=blocked)


# --- Running --------------------------------------------------------------------------------------

def build_command(program: str, args: list[str], target: str, url: str = "") -> list[str]:
    """The argument list for one call. Only the placeholders are replaced (never str.format), and each argument
    stays one list item. The values come from the validated target and the pipeline's own URLs, which contain no
    braces, so nothing is replaced twice."""
    return [program] + [arg.replace("{target}", target).replace("{url}", url) for arg in args]


def clean_output(text: str) -> str:
    """A tool's output as plain text, Windows line ends unified. Removed: terminal control strings with what they
    carry (window titles, hyperlinks), ended by BEL, ESC \\ or the 8-bit ST, or else up to the end of their line
    or the next ESC;
    colour and cursor codes; control characters; and the invisible characters that could hide text or reorder it
    (bidi controls and marks, zero-width space, word joiner, U+2060-U+2064, U+180E, the byte order mark and the tag
    characters). The zero-width non-joiner and joiner stay, because Persian and Indic text and emoji need them. The
    scan takes linear time whatever the output holds."""
    text = _CONTROL_STRING_RE.sub("", text.replace("\r\n", "\n"))
    return _CONTROL_RE.sub("", _ANSI_RE.sub("", text))


# --- Helpers --------------------------------------------------------------------------------------

def _check_name(name: str) -> str:
    key = name.strip().lower()
    if not _NAME_RE.fullmatch(key):
        raise CustomToolError("Name: use 1-32 lower-case letters, digits, - or _, starting with a letter "
                              "(for example hdrcheck).")
    if key in TOOLS:
        raise CustomToolError(f"Name: {key} is a built-in tool. Choose another name.")
    if key == "constructor":  # the dashboard looks names up in plain objects, where this one is taken
        raise CustomToolError("Name: constructor is reserved by the dashboard. Choose another name.")
    return key


def _check_program(program: str, allowed: frozenset[str], look_up: bool) -> str:
    text = program.strip()
    if not text or not text.isprintable() or text.startswith("-") or \
            not (_BARE_PROGRAM_RE.fullmatch(text) or _is_absolute(text)):
        raise CustomToolError("Program: give the executable's name (for example curl) or its full path (for example "
                              "/usr/bin/curl or C:\\Tools\\curl.exe); a relative path, a network share and a leading - "
                              "are not accepted.")
    problem = program_problem(text)
    if problem:
        raise CustomToolError(problem)
    key = _program_key(text)
    if key not in allowed:
        raise CustomToolError(f"Program: {_cut(_base_name(text))} is not on the list of allowed programs "
                              f"({', '.join(_shown_names(allowed)) or 'none'}). Add it to HYBRIDSEC_CUSTOM_PROGRAMS in "
                              ".env if it only gathers information.")
    pinned = allowed.paths.get(key, ()) if isinstance(allowed, AllowedPrograms) else ()
    # A bare name is looked up on PATH when it runs, so only the absolute path itself can match a pinned file.
    if pinned and not (_is_absolute(text) and _file_key(text) in {_file_key(path) for path in pinned}):
        files = " or ".join(_cut_path(path) for path in pinned)
        which = "that full path" if len(pinned) == 1 else "one of those full paths"
        raise CustomToolError(f"Program: HYBRIDSEC_CUSTOM_PROGRAMS allows {_cut(key)} only as {files}, so register "
                              f"{which}. To allow {_cut(key)} from any folder, add its name alone to the list in "
                              ".env.")
    if look_up:
        _path, problem = find_program(text)
        if problem:
            raise CustomToolError(problem)
    return text


def _check_args(args: list[str], scope: str, program_key: str = "") -> list[str]:
    has_target = has_url = False
    for token in args:
        if not 1 <= len(token) <= 200 or not token.isprintable() or any(char.isspace() for char in token):
            raise CustomToolError("Arguments: each argument must be 1-200 printable characters without spaces. "
                                  "Separate arguments with spaces in the form; quoting is not supported.")
        if "'" in token or '"' in token:
            raise CustomToolError("Arguments: quotes are not supported. Each space-separated piece is passed to the "
                                  "program as it is, so write the argument without quotes or leave it out.")
        letter = _curl_value_letter(token) if program_key == "curl" else ""
        if token.split("=", 1)[0] in CREDENTIAL_OPTIONS or letter in _CURL_CREDENTIAL_LETTERS:
            raise CustomToolError(f"Arguments: {_cut(token)} passes a user name, password, certificate or cookie. "
                                  "Secrets would be stored with every run and shown in its reports; keep them in the "
                                  "tool's own configuration file or environment.")
        rest = _PLACEHOLDER_RE.sub("", token)
        if "{" in rest or "}" in rest:
            raise CustomToolError(f"Arguments: {_cut(token)} contains {{ or }} that is not a placeholder. Only "
                                  "{target} and {url}, in lower case, are filled in.")
        has_target = has_target or "{target}" in token
        has_url = has_url or "{url}" in token
        _check_host(token, program_key)
        if any(word in token.lower() for word in REFUSED_WORDS):
            raise CustomToolError(f"Arguments: {_cut(token)} asks for brute-force, exploit, fuzzing or attack "
                                  "behaviour, which HybridSec does not run.")
        if _looks_secret(rest):
            raise CustomToolError(f"Arguments: {_cut(token)} looks like it carries a password, key or token. Secrets "
                                  "would be stored with every run and shown in its reports; keep them in the tool's "
                                  "own configuration file or environment.")
    if scope == "target":
        if has_url:
            raise CustomToolError("Arguments: {url} is only filled in for a tool that runs once per web URL. Choose "
                                  "that option or use {target}.")
        if not has_target:
            raise CustomToolError("Arguments: a tool that runs once on the target needs {target} in its arguments.")
    elif not has_url:
        raise CustomToolError("Arguments: a tool that runs once per web URL needs {url} in its arguments.")
    return list(args)


def _check_host(token: str, program_key: str) -> None:
    """Refuse an argument that could send the tool somewhere other than {target} or {url}: the forms the module
    docstring lists. Full-width digits, dots and letters count as their plain forms. %-escapes are decoded for the
    URL, address and host-name tests only: the [ ], @ and two-slash tests read the text as written."""
    scope_note = "Only {target} and {url} may point the tool at a host, so the run's scope check applies."
    if _routing_option(token, program_key):
        raise CustomToolError(f"Arguments: {_cut(token)} sends the tool's traffic through another host or reads "
                              f"options or targets from a file. {scope_note}")
    plain = unicodedata.normalize("NFKC", token).replace("\u3002", ".")  # the ideographic full stop is a dot too
    written = _PLACEHOLDER_RE.sub("", plain)
    # The tools decode %-escapes in a host name (%31%30.0.0.1, %65vil.example), so these tests read them decoded.
    decoded = urllib.parse.unquote(written)
    if "://" in decoded or _has_address(decoded):
        raise CustomToolError(f"Arguments: {_cut(token)} names a fixed address or URL. {scope_note}")
    # A placeholder is read as a letter here: the // of {url}//admin is inside the URL's path, not where a path starts.
    if _network_path(_PLACEHOLDER_RE.sub("x", plain), program_key):
        if _NT_PREFIX_RE.search(plain):
            raise CustomToolError(f"Arguments: {_cut(token)} uses the \\??\\ prefix, which hands a path to Windows "
                                  "unchanged and can reach a network share (\\??\\UNC\\server\\share). Write the "
                                  "path in its usual form, for example C:\\out.txt: only {target} and {url} may point "
                                  "the tool at a host.")
        raise CustomToolError(f"Arguments: {_cut(token)} holds two slashes or backslashes in a row at the start of a "
                              "path (or two backslashes), which Windows reads as a network path (\\\\server\\share or "
                              "//server/share). Use a file on a local drive: only {target} and {url} may point the "
                              "tool at a host.")
    if program_key == "curl" and ("[" in written or "]" in written):
        raise CustomToolError(f"Arguments: {_cut(token)} uses curl's [ ] ranges, which can reach many hosts or paths "
                              f"in one call. {scope_note}")
    if "@" in written and not (program_key == "dig" and token == "@{target}"):  # dig @{target} asks the target itself
        raise CustomToolError(f"Arguments: {_cut(token)} contains @, which names a server (dig @server), a user at a "
                              "host or a file to read (curl -d @file). Leave it out: only {target} and {url} may point "
                              "the tool at a host, and options are not read from files.")
    if _looks_like_host(decoded, program_key):
        # A drive path glued to a short option (wget -OC:/page.html) reads as one when the program's option letters
        # are not known (see _VALUE_LETTERS): it can be given as an argument of its own.
        glued = " A path on a drive can also be given as an argument of its own (-O C:/page.html)." \
            if program_key not in _VALUE_LETTERS and re.match(r"-\w*[A-Za-z]:", token) else ""
        raise CustomToolError(f"Arguments: {_cut(token)} looks like a host name (localhost or a dotted name such as "
                              "dns.example), and only {target} and {url} may point the tool at a host. If it is a file "
                              "name, write it with its folder, for example ./out.txt." + glued)


def _routing_option(token: str, program_key: str) -> bool:
    """True when the argument is one of the program's _ROUTING_OPTIONS: a long name or a prefix of one, or a
    short-option word (bundled or not) that uses one of the letters."""
    long_names, letters = _ROUTING_OPTIONS.get(program_key, ((), ""))
    name = token.split("=", 1)[0]
    if name in long_names or \
            (name.startswith("--") and len(name) > 2 and any(option.startswith(name) for option in long_names)):
        return True
    return any(letter in letters for letter in _short_letters(token, _VALUE_LETTERS.get(program_key, "")))


def _has_address(text: str) -> bool:
    """An IPv4 address anywhere in the text, an IPv6 address (with :: or in brackets, or written out in full
    between = , and @), or an address range."""
    if _IPV4_RE.search(text) or _IPV6_RE.search(text):
        return True
    return any(_is_address(piece) for piece in re.split(r"[=,@]", text))


def _network_path(text: str, program_key: str) -> bool:
    """True when two slashes or backslashes start a path (the argument, a piece after = , : @ or <, as in curl's
    -F name=<file, or the value glued to a short option as in -T//srv/share), when two backslashes stand anywhere,
    or when the NT prefix \\??\\ appears: Windows reads all of them as a network path (\\\\server\\share,
    //server/share, /\\server, \\??\\UNC\\server). Two slashes inside a path ({url}/a//b) are not one."""
    if "\\\\" in text or _NT_PREFIX_RE.search(text):
        return True
    starts = [*re.split(r"[=,:@<]", text), _short_option_value(text, program_key)]
    return any(re.match(r"[\\/]{2}", start) for start in starts)


def _short_option_value(token: str, program_key: str) -> str:
    """The value glued to a short option (//srv/share in -T//srv/share), or "" when the argument is not a short-
    option word. The option letters end after the first one that takes a value (see _VALUE_LETTERS); for a
    program whose value letters are not known, before the first character that is not a letter or digit."""
    if token[:1] != "-" or token[1:2] in ("", "-"):
        return ""
    value_letters = _VALUE_LETTERS.get(program_key, "")
    for index, char in enumerate(token[1:], start=1):
        if char in value_letters:
            return token[index + 1:]
        # For a program whose value letters are known, every other character is an option letter (curl's -# is
        # --progress-bar, as in -#T//srv); for another program a non-alphanumeric character starts the value.
        if not value_letters and not (char.isascii() and char.isalnum()):
            return token[index:]
    return ""


def _looks_like_host(text: str, program_key: str = "") -> bool:
    """A piece of the text between = , : and @ that reads as a host name: localhost, or a dotted name whose last
    label is letters (also when a path, a ? query or a # fragment follows, as in dns.example/x or dns.example?q).
    Leading and trailing dots and dashes are ignored, so {url}.evil.example counts. So are the slashes and
    backslashes that start a piece after a colon, so the host of a URL with one slash (http:/dns.example,
    http:\\dns.example) counts while a header such as X-Original-URL:/admin does not; after a drive letter
    (C:/out.txt, also after curl's < as in name=<C:/notes.txt, or glued to a short option as in -oC:/out.txt) they
    stay, since that is a file."""
    parts = re.split(r"([=,:@])", text)  # pieces at the even indexes, each separator just before its piece
    for index in range(0, len(parts), 2):
        piece = parts[index]
        before = parts[index - 2] if index else ""
        drive = re.fullmatch(r"(?:.*<)?[A-Za-z]", before) or \
            re.fullmatch(r"[A-Za-z]", _short_option_value(before, program_key))
        if index and parts[index - 1] == ":" and not drive:
            piece = piece.lstrip("/\\")
        name = re.split(r"[/?#]", piece, maxsplit=1)[0].strip(".-").lower()
        if name == "localhost" or _HOST_NAME_RE.fullmatch(name):
            return True
    return False


def _is_absolute(program: str) -> bool:
    """An absolute path on this system. os.path.isabs is not used: on Windows it accepts network shares and
    device paths, which are refused."""
    if os.name == "nt":
        return _WINDOWS_ABSOLUTE_RE.fullmatch(program) is not None
    return program.startswith("/")


def _entry(name: str) -> str:
    """An allow-list entry as the rules use it: a relative path is made absolute against the current folder (the one
    HybridSec was started from); an absolute path, a drive path and a name stay as written."""
    if _is_path_entry(name) and not re.match(r"[\\/]|[A-Za-z]:", name):
        return os.path.abspath(name)
    return name


def _is_path_entry(name: str) -> bool:
    """True when an allow-list entry is written as a path (it holds a slash or a backslash), not as a name."""
    return "/" in name or "\\" in name


def _file_key(path: str) -> str:
    """How two spellings of one file compare: the real path (links followed, . and .. resolved, relative to the
    current folder when not absolute), in the system's letter case."""
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):  # a name the system cannot look up compares as written
        return os.path.normcase(path)


def _inside(path: str, folder: str) -> bool:
    """True when `path` is `folder` or anything below it (case-insensitively where the system is)."""
    path, folder = (os.path.normcase(p.removeprefix("\\\\?\\")) for p in (path, folder))
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # different drives, or one path relative
        return False


def _base_name(program: str) -> str:
    """The file name, lower case, with the trailing dots and spaces Windows ignores removed."""
    return re.split(r"[\\/]", program.strip())[-1].lower().rstrip(". ")


def _program_key(program: str) -> str:
    """The name the rules compare: the file name without .exe/.com and without a trailing version, so python3.12
    and bash.exe count as python and bash."""
    name = re.sub(r"\.(exe|com)$", "", _base_name(program))
    return re.sub(r"[\d.]+$", "", name) or name


def _shown_names(allowed: frozenset[str]) -> list[str]:
    """The allowed programs a message lists: the entries as written, or for a plain set of keys, those keys."""
    names = allowed.shown if isinstance(allowed, AllowedPrograms) else \
        [key for key in allowed if program_problem(key) is None]
    return sorted(names, key=str.lower)


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_network(text.strip("[]"), strict=False)
    except ValueError:
        return False
    return True


def _short_letters(token: str, value_letters: str) -> str:
    """The option letters of a short-option word such as -s, -sK or -uadmin:pw ("" when it is not one): the
    letters up to and including the first that takes a value, since the rest of the word is that value."""
    if token[:1] != "-" or token[1:2] in ("", "-"):
        return ""
    letters = ""
    for letter in token[1:]:
        letters += letter
        if letter in value_letters:
            break
    return letters


def _curl_value_letter(token: str) -> str:
    """The value-taking letter of a curl short-option word such as -u, -su or -uadmin:pw ("" when there is none):
    curl reads the letters of a bundle until the first one that takes a value."""
    last = _short_letters(token, _VALUE_LETTERS["curl"])[-1:]
    return last if last in _CURL_VALUE_LETTERS else ""


def _looks_secret(text: str) -> bool:
    """Best effort: a word that names a secret, or a long letters-and-digits value that looks like a key, as the
    whole argument or after its last =. Base64 padding (a trailing = or ==) is ignored."""
    lowered = text.lower()
    if any(word in lowered for word in SECRET_WORDS):
        return True
    whole = text.rstrip("=")
    return _key_like(whole) or _key_like(whole.rsplit("=", 1)[-1])


def _key_like(value: str) -> bool:
    return (not value.startswith("-") and _KEY_LIKE_RE.fullmatch(value) is not None
            and any(c.isalpha() for c in value) and any(c.isdigit() for c in value))


def _cut(text: str, limit: int = 80) -> str:
    """Operator text echoed in a message, cut so a huge value cannot produce a huge answer."""
    return text if len(text) <= limit else text[:limit] + "..."


def _cut_path(path: str, limit: int = 80) -> str:
    """A path echoed in a message, cut in the middle when it is long, so its start and its file name (the part
    that usually says what is wrong) stay visible."""
    if len(path) <= limit:
        return path
    head = limit // 3
    return path[:head] + "..." + path[-(limit - head - 3):]
