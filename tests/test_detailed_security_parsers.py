"""Edge-case tests for the gate between user input and the scanners (app/security.py), the output parsers
(app/tools/parsers.py), the tool catalogue (app/tools/registry.py) and the subprocess runner (app/tools/runner.py).

One behaviour per test, named after the requirement it checks. Everything runs offline: no scanner is ever
started, the only child processes are short Python one-liners, and the environment is the private .env and
data directory that tests/test_api.py sets up when it is imported.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

import pytest

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app.config import BASE_DIR, ENV_FILE, settings
from app.schemas import CustomToolCreate, PortFinding
from app.security import (
    TargetError,
    check_scope,
    is_hostname,
    is_ipv6_target,
    is_network_range,
    matches_allowlist_entry,
    normalize_target,
    validate_allowlist_entry,
    validate_execution_target,
)
from app.tools import custom, parsers, registry, runner
from app.tools.runner import run_command


def test_suite_runs_against_a_private_env_file():
    """The tests never read or write the developer's real .env: HYBRIDSEC_ENV_FILE points at a throwaway file."""
    private = Path(os.environ["HYBRIDSEC_ENV_FILE"]).resolve()
    assert private != (BASE_DIR / ".env").resolve()
    assert Path(ENV_FILE).resolve() == private


# --- normalize_target -----------------------------------------------------------------------------

def test_normalize_target_returns_canonical_forms():
    """Addresses and names come back in one canonical spelling, so the same target is always stored the same way."""
    assert normalize_target("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"  # IPv6 is compressed
    assert normalize_target("2001:DB8::1") == "2001:db8::1"  # and lower-cased
    assert normalize_target("::ffff:10.10.20.5") == "::ffff:10.10.20.5"  # IPv4-mapped IPv6 is kept as written
    assert normalize_target("My-Host.LAB.Example.EDU") == "my-host.lab.example.edu"  # hyphens allowed, case folded
    assert normalize_target("localhost") == "localhost"  # a single label is a valid name
    assert normalize_target("xn--bcher-kva.example") == "xn--bcher-kva.example"  # punycode is plain ASCII
    assert normalize_target("10.10.20.5/24") == "10.10.20.0/24"  # host bits are cleared
    assert normalize_target("10.10.20.5/024") == "10.10.20.0/24"  # a zero-padded prefix length is read as a number
    assert normalize_target("example.1a") == "example.1a"  # a top-level label only needs one letter


def test_normalize_target_cidr_size_limit_is_exactly_24_and_120():
    """A block of 256 addresses (/24 IPv4, /120 IPv6) is the largest a run may scan; one bit more is refused."""
    assert normalize_target("10.10.20.0/24") == "10.10.20.0/24"
    assert normalize_target("10.10.20.0/25") == "10.10.20.0/25"
    assert normalize_target("2001:db8::/120") == "2001:db8::/120"
    assert normalize_target("2001:db8::/121") == "2001:db8::/121"
    for too_large in ("10.10.20.0/23", "0.0.0.0/0", "2001:db8::/119", "::/0"):
        with pytest.raises(TargetError, match="too large"):
            normalize_target(too_large)


def test_normalize_target_rejects_option_list_and_range_syntax():
    """Anything a shell or nmap could read as more than one plain target is refused, with a message that says why."""
    cases = [
        ("10.10.20.5;id", "characters"),  # command separator
        ("10.10.20.5|cat", "characters"),  # pipe
        ("`id`", "characters"),  # backticks
        ("a&b", "characters"),  # background operator
        ("a\\b", "characters"),  # backslash escape
        ("a!b", "characters"),  # history expansion
        ("a\tb", "characters"),  # tab, which nmap reads as an argument separator
        ("10.10.20.1-5", "ranges"),  # nmap octet range inside the last octet
        ("1-254", "ranges"),  # a bare octet range
        ("10.0-255.0.1", "ranges"),  # a range in an inner octet
        # A single address that is not written as four plain numbers is refused too, but it is not a range: the
        # message says how to write it instead (issue 27 of the 12 November test round).
        ("2130706433", "not a standard dotted IP address"),  # 127.0.0.1 written as one decimal number
        ("1.2.3", "not a standard dotted IP address"),  # three octets, which nmap would complete itself
        ("127.1", "not a standard dotted IP address"),  # the short form of 127.0.0.1
        ("256.1.1.1", "not a standard dotted IP address"),  # octet out of range
        ("010.0.0.1", "not a standard dotted IP address"),  # leading zero, ambiguous between octal and decimal
        ("127.0.0.01", "not a standard dotted IP address"),
        ("0x7f.0.0.1", "alphabetic"),  # hexadecimal octets
    ]
    for raw, reason in cases:
        with pytest.raises(TargetError, match=reason) as excinfo:
            normalize_target(raw)
        if reason.startswith("not a standard"):  # it names what was typed and shows the plain form
            message = str(excinfo.value)
            assert message.startswith(f"'{raw}' is not") and "for example 127.0.0.1" in message, raw
            assert "range" not in message, raw


def test_normalize_target_rejects_urls_ports_and_paths():
    """Only a bare host, address or CIDR is a target: schemes, ports, paths and brackets are refused."""
    cases = [
        ("[::1]", "not a valid"),  # bracketed IPv6 is URL syntax
        ("[2001:db8::1]:443", "not a valid"),
        ("lab.example.edu:8080", "not a valid"),  # host with a port
        ("127.0.0.1:8080", "not a valid"),
        ("https://10.10.20.5/", "URL or path"),  # scheme
        ("lab.example.edu/path", "URL or path"),  # path
        ("10.10.20.0/", "URL or path"),  # slash without a prefix length
        ("10.10.20.5/-1", "URL or path"),  # negative prefix length
        ("lab.example.edu/24", "Invalid CIDR"),  # prefix length on a name
        ("10.10.20.0/33", "Invalid CIDR"),  # prefix length beyond 32
    ]
    for raw, reason in cases:
        with pytest.raises(TargetError, match=reason):
            normalize_target(raw)


def test_normalize_target_enforces_hostname_grammar_and_ascii():
    """Labels are ASCII letters, digits and inner hyphens; anything else, including look-alike Unicode, is refused."""
    for raw in ("lab.example.edu.",  # trailing dot
                "host-.example.edu", "a.-b.example.edu",  # hyphen at a label edge
                "under_score.example.edu",  # underscore
                "läb.example.edu",  # non-ASCII letter
                "\uff45xample.com",  # full-width letter
                "\uff11\uff12\uff17.0.0.1",  # full-width digits
                "lab.example.edu\u200b"):  # zero-width space
        with pytest.raises(TargetError, match="not a valid"):
            normalize_target(raw)
    with pytest.raises(TargetError, match="dash"):
        normalize_target("-host.example.edu")  # a leading dash would be read as an nmap option


def test_normalize_target_enforces_dns_length_limits():
    """A label may have 63 characters and a name 253, as DNS allows; one more character is refused."""
    assert normalize_target("a" * 63 + ".example.edu").startswith("a" * 63)
    with pytest.raises(TargetError):
        normalize_target("a" * 64 + ".example.edu")
    name_253 = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 57]) + ".edu"
    assert len(name_253) == 253 and normalize_target(name_253) == name_253
    with pytest.raises(TargetError):
        normalize_target(".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 58]) + ".edu")  # 254 characters


def test_normalize_target_rejects_empty_input():
    """An empty, whitespace-only or missing target gets the "empty" message rather than a confusing one."""
    for raw in ("", "   ", "\n\t", None):
        with pytest.raises(TargetError, match="empty"):
            normalize_target(raw)


def test_normalize_target_rejects_oversized_input_quickly():
    """Very long input is refused immediately: the hostname check cannot be made to run for seconds."""
    started = time.perf_counter()
    for raw in ("a" * 20_000, "a-" * 10_000 + "a", "1." * 10_000 + "1"):
        with pytest.raises(TargetError):
            normalize_target(raw)
    assert time.perf_counter() - started < 0.2


# --- Allow-list entries ---------------------------------------------------------------------------

def test_allowlist_entry_is_normalised_and_may_be_any_size():
    """An entry limits what may be scanned, so unlike a target it may be a large CIDR; names are lower-cased."""
    assert validate_allowlist_entry("*.LAB.Example.EDU") == "*.lab.example.edu"
    assert validate_allowlist_entry("*.local") == "*.local"
    assert validate_allowlist_entry(" Lab.Example.EDU ") == "lab.example.edu"
    assert validate_allowlist_entry("LOCALHOST") == "localhost"
    assert validate_allowlist_entry("0.0.0.0/0") == "0.0.0.0/0"
    assert validate_allowlist_entry("::/0") == "::/0"
    assert validate_allowlist_entry("2001:db8::/32") == "2001:db8::/32"
    assert validate_allowlist_entry("10.10.20.5/24") == "10.10.20.0/24"  # host bits cleared


def test_allowlist_entry_rejects_malformed_patterns():
    """Wildcards must be *.domain with an alphabetic top-level label; everything else obeys the target rules."""
    for raw in ("*.", "*", "**.lab.example.edu", "a.*.example.edu", "* .lab.example.edu",
                "*.lab.example.123", "*.-lab.example.edu", "*.lab.example.edu.",
                "10.0.0.0/33", "10.10.20.1-5", "10.10.20.5;id"):
        with pytest.raises(TargetError):
            validate_allowlist_entry(raw)
    for raw in ("", "   ", None):
        with pytest.raises(TargetError, match="Empty"):
            validate_allowlist_entry(raw)


def test_exact_entry_matches_the_same_address_in_any_spelling():
    """A plain IP or host entry matches only that one target; the entry's letter case and spelling do not matter."""
    assert matches_allowlist_entry("10.10.20.5", "10.10.20.5")
    assert not matches_allowlist_entry("10.10.20.5", "10.10.20.6")
    assert matches_allowlist_entry("::1", "::1")
    assert matches_allowlist_entry("2001:db8::1", "2001:0db8::1")  # same address, different spelling
    assert matches_allowlist_entry("lab.example.edu", "LAB.EXAMPLE.EDU")
    assert matches_allowlist_entry("10.10.20.5", " 10.10.20.5 ")  # hand-edited .env with spaces
    assert not matches_allowlist_entry("10.10.20.5", "lab.example.edu")


def test_cidr_entry_matches_by_containment_within_the_same_address_family():
    """A CIDR entry allows the addresses inside it, and an IPv6 entry never allows an IPv4 target or a name."""
    assert matches_allowlist_entry("10.10.20.5", "10.10.20.0/24")
    assert not matches_allowlist_entry("10.10.21.5", "10.10.20.0/24")
    assert matches_allowlist_entry("10.10.20.5", "10.10.20.5/32")
    assert matches_allowlist_entry("2001:db8::1", "2001:db8::/32")
    assert matches_allowlist_entry("2001:db8::1", "2001:DB8::/32")
    assert not matches_allowlist_entry("10.10.20.5", "2001:db8::/32")
    assert not matches_allowlist_entry("::1", "127.0.0.1")
    assert not matches_allowlist_entry("lab.example.edu", "10.0.0.0/8")


def test_cidr_target_must_fit_entirely_inside_the_entry():
    """A block target is allowed only when every address in it is allowed: a /24 does not fit in a /25."""
    assert matches_allowlist_entry("10.10.20.0/24", "10.10.0.0/16")
    assert matches_allowlist_entry("10.10.20.0/24", "10.10.20.0/24")
    assert not matches_allowlist_entry("10.10.20.0/24", "10.10.20.0/25")
    assert matches_allowlist_entry("2001:db8::/120", "2001:db8::/32")
    assert not matches_allowlist_entry("10.10.20.0/24", "*.lab.example.edu")  # a wildcard never allows a block


def test_wildcard_entry_matches_subdomains_only():
    """*.lab.example.edu allows hosts under that domain, not the bare domain or look-alike names."""
    assert matches_allowlist_entry("web.lab.example.edu", "*.lab.example.edu")
    assert matches_allowlist_entry("deep.web.lab.example.edu", "*.lab.example.edu")  # any depth
    assert matches_allowlist_entry("web.lab.example.edu", "*.LAB.EXAMPLE.EDU")  # entry case ignored
    assert not matches_allowlist_entry("lab.example.edu", "*.lab.example.edu")  # the domain itself
    assert not matches_allowlist_entry("evil-lab.example.edu", "*.lab.example.edu")  # suffix without the dot
    assert not matches_allowlist_entry("xlab.example.edu", "*.lab.example.edu")
    assert not matches_allowlist_entry("lab.example.edu.attacker.test", "*.lab.example.edu")  # prefix attack


def test_unusable_entry_never_matches_and_never_raises():
    """A damaged or empty entry in a hand-edited .env simply allows nothing; scope checks keep working."""
    assert not matches_allowlist_entry("10.10.20.5", "bad host!")
    assert not matches_allowlist_entry("10.10.20.5", "")
    assert not matches_allowlist_entry("10.10.20.5", "*.20.5")  # wildcards never match addresses
    assert not matches_allowlist_entry("web.lab.example.edu", "10.10.20.0/24")


# --- check_scope and validate_execution_target ----------------------------------------------------

def test_empty_allowlist_allows_every_valid_target(monkeypatch):
    """With no allow-list configured, scope is not restricted: any syntactically valid target passes."""
    monkeypatch.setattr(settings, "allowed_targets", [])
    for target in ("10.10.20.5", "2001:db8::/120", "web.lab.example.edu", "localhost"):
        assert check_scope(target) is None


def test_check_scope_accepts_any_matching_entry_and_explains_rejections(monkeypatch):
    """One matching entry is enough; a rejection names the target, the allowed entries and the Settings page."""
    monkeypatch.setattr(settings, "allowed_targets", ["10.10.20.0/24", "*.lab.example.edu"])
    for target in ("10.10.20.7", "10.10.20.0/25", "web.lab.example.edu"):
        assert check_scope(target) is None
    with pytest.raises(TargetError) as excinfo:
        check_scope("10.10.21.5")
    message = str(excinfo.value)
    assert "'10.10.21.5' is outside the allowed scope" in message
    assert "10.10.20.0/24, *.lab.example.edu" in message and "Settings page" in message
    with pytest.raises(TargetError, match="outside the allowed scope"):
        check_scope("lab.example.edu")  # the bare domain is not covered by the wildcard


def test_authorization_flag_is_checked_before_anything_else():
    """Without the authorized flag nothing else is examined: valid and invalid targets get the same answer."""
    for raw in ("10.10.20.5", "10.10.20.5;id", ""):
        with pytest.raises(TargetError, match="authorized"):
            validate_execution_target(raw, authorized=False)


def test_target_syntax_is_checked_before_scope_and_the_normalised_target_is_returned(monkeypatch):
    """Order of the checklist: syntax, then scope; the caller receives the canonical target that passed both."""
    monkeypatch.setattr(settings, "allowed_targets", ["10.10.20.0/24", "*.lab.example.edu"])
    with pytest.raises(TargetError, match="characters"):  # not the scope message
        validate_execution_target("10.10.20.5;id", authorized=True)
    assert validate_execution_target(" 10.10.20.7 ", authorized=True) == "10.10.20.7"
    assert validate_execution_target("WEB.Lab.Example.EDU", authorized=True) == "web.lab.example.edu"
    with pytest.raises(TargetError, match="outside the allowed scope"):
        validate_execution_target("10.10.21.5", authorized=True)


# --- Target properties ----------------------------------------------------------------------------

@pytest.mark.parametrize("target,ipv6,network_range,hostname", [
    ("10.10.20.5", False, False, False),
    ("::1", True, False, False),
    ("10.10.20.0/24", False, True, False),
    ("10.10.20.0/31", False, True, False),  # two addresses is already a range
    ("2001:db8::/120", True, True, False),
    ("web.lab.example.edu", False, False, True),
    ("localhost", False, False, True),
])
def test_target_properties_classify_validated_targets(target, ipv6, network_range, hostname):
    """is_ipv6_target picks nmap -6, is_network_range requires nmap, is_hostname makes the web stages probe by name."""
    assert (is_ipv6_target(target), is_network_range(target), is_hostname(target)) == (ipv6, network_range, hostname)


def test_single_address_cidr_normalises_to_the_bare_address():
    """A /32 or /128 block is one host, so it becomes that address: is_hostname() stays False and the web stages
    build a normal URL instead of "http://10.10.20.5/32" (a defect found and fixed during the test review)."""
    for raw, address in (("10.10.20.5/32", "10.10.20.5"), ("2001:db8::1/128", "2001:db8::1"), ("::1/128", "::1")):
        target = normalize_target(raw)
        assert target == address
        assert not is_hostname(target) and not is_network_range(target)
    assert is_ipv6_target(normalize_target("2001:db8::1/128"))


# --- Nmap parser ----------------------------------------------------------------------------------

NMAP_HEAD = '<?xml version="1.0"?><nmaprun scanner="nmap">'
# Five hosts that are up (one of them hit --host-timeout, one has no address), one host that is down, and a
# mix of open, closed, filtered and open|filtered ports.
NMAP_MULTI_HOST = (
    NMAP_HEAD
    + '<host><status state="up"/><address addr="10.10.20.5" addrtype="ipv4"/>'
      '<address addr="00:11:22:33:44:55" addrtype="mac"/>'
      '<hostnames><hostname name="web.lab.example.edu" type="PTR"/><hostname name="alias.lab.example.edu" type="user"/></hostnames>'
      '<ports>'
      '<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>'
      '<service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu Linux; protocol 2.0"/></port>'
      '<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp"/></port>'
      '<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>'
      '<port protocol="udp" portid="161"><state state="open|filtered"/><service name="snmp"/></port>'
      '<port protocol="tcp" portid="8443"><state state="open"/><service name="https-alt" tunnel="ssl"/></port>'
      '<port protocol="tcp" portid="9999"><state state="open"/></port>'
      '</ports></host>'
    + '<host><status state="down"/><address addr="10.10.20.6" addrtype="ipv4"/></host>'
    + '<host><status state="up"/><address addr="2001:db8::5" addrtype="ipv6"/><ports>'
      '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port></ports></host>'
    + '<host><status state="up"/><address addr="10.10.20.7" addrtype="ipv4"/><address addr="2001:db8::7" addrtype="ipv6"/>'
      '<ports><port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/></port></ports></host>'
    + '<host><status state="up"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port>'
      '</ports></host>'
    + '<host timedout="true"><status state="up"/><address addr="10.10.20.9" addrtype="ipv4"/></host>'
    + '</nmaprun>'
)


def test_nmap_parser_reads_every_host_and_keeps_only_open_ports():
    """All hosts in one report are read; closed, filtered and open|filtered ports are not findings."""
    result = parsers.parse_nmap_xml_full(NMAP_MULTI_HOST)
    assert (result.hosts_up, result.hosts_timed_out, result.truncated) == (5, 1, False)
    assert [(p.host, p.port) for p in result.ports] == [
        ("web.lab.example.edu (10.10.20.5)", 22), ("web.lab.example.edu (10.10.20.5)", 8443),
        ("web.lab.example.edu (10.10.20.5)", 9999), ("2001:db8::5", 80), ("10.10.20.7", 443), ("unknown", 21),
    ]
    assert all(p.state == "open" for p in result.ports)


def test_nmap_parser_keeps_service_details_and_tolerates_a_missing_service_element():
    """Product, version and extra info are copied from the banner; a port without <service> is still reported."""
    ports = {p.port: p for p in parsers.parse_nmap_xml_full(NMAP_MULTI_HOST).ports}
    ssh = ports[22]
    assert (ssh.service, ssh.product, ssh.version, ssh.extra, ssh.protocol) == (
        "ssh", "OpenSSH", "9.6p1", "Ubuntu Linux; protocol 2.0", "tcp")
    assert ssh.is_web is False
    bare = ports[9999]
    assert (bare.service, bare.product, bare.version, bare.extra, bare.is_web) == ("", "", "", "", False)
    assert ports[8443].service == "ssl/https-alt" and ports[8443].is_web is True  # tunnel prefixed, TLS web port
    assert ports[443].service == "ssl/http" and ports[80].product == "nginx"


def test_nmap_parser_labels_hosts_by_name_and_prefers_the_ipv4_address():
    """A resolved name is shown as "name (address)"; dual-stack hosts show IPv4; an address-less host is "unknown"."""
    hosts = [p.host for p in parsers.parse_nmap_xml_full(NMAP_MULTI_HOST).ports]
    assert hosts[0] == "web.lab.example.edu (10.10.20.5)"  # the first hostname wins, the MAC address is ignored
    assert "10.10.20.7" in hosts and "2001:db8::7" not in hosts  # dual-stack host labelled by IPv4
    assert "2001:db8::5" in hosts  # IPv6-only host keeps its IPv6 address
    assert hosts[-1] == "unknown"


def test_nmap_parser_handles_no_hosts_and_non_xml_output():
    """An empty report gives zero hosts without a truncation flag; text that is not XML is flagged as cut off."""
    for text in ('<?xml version="1.0"?><nmaprun></nmaprun>', "", "   \n  "):
        result = parsers.parse_nmap_xml_full(text)
        assert (result.ports, result.hosts_up, result.hosts_timed_out, result.truncated) == ([], 0, 0, False)
    garbage = parsers.parse_nmap_xml_full("Starting Nmap 7.95 ( https://nmap.org )")
    assert garbage.truncated is True and garbage.ports == [] and garbage.hosts_up == 0


def test_nmap_parser_salvages_complete_hosts_from_cut_off_xml():
    """When Nmap was killed mid-write, every complete <host> block is kept and the result is marked truncated."""
    cut = NMAP_MULTI_HOST[: NMAP_MULTI_HOST.find("</host>") + len("</host>")] + '<host><status state="up"/><addr'
    result = parsers.parse_nmap_xml_full(cut)
    assert result.truncated is True and result.hosts_up == 1
    assert [p.port for p in result.ports] == [22, 8443, 9999]
    ports, hosts_up = parsers.parse_nmap_xml(cut)
    assert len(ports) == 3 and hosts_up == 1


# --- URL building ---------------------------------------------------------------------------------

def test_url_for_chooses_scheme_and_omits_default_ports():
    """The probe URL uses https for TLS-looking ports and leaves out the port when it is the scheme's default."""
    cases = [
        (80, "http", "http://10.10.20.5"),  # default port left out
        (443, "http", "https://10.10.20.5"),  # 443 is https even when nmap says "http"
        (8080, "http", "http://10.10.20.5:8080"),
        (8443, "", "https://10.10.20.5:8443"),  # well-known TLS port with an unidentified service
        (8000, "ssl/http", "https://10.10.20.5:8000"),  # TLS tunnel reported by nmap
        (80, "ssl/http", "https://10.10.20.5:80"),  # TLS on port 80 keeps the port because it is not https's default
        (9443, "unknown", "https://10.10.20.5:9443"),
        (81, "http", "http://10.10.20.5:81"),
    ]
    for port, service, expected in cases:
        assert parsers.url_for(PortFinding(host="10.10.20.5", port=port, service=service)) == expected, (port, service)


def test_url_for_brackets_ipv6_and_applies_the_host_override():
    """IPv6 addresses are bracketed exactly once, display labels yield their address, and an override replaces it."""
    assert parsers.url_for(PortFinding(host="2001:db8::5", port=8080, service="http")) == "http://[2001:db8::5]:8080"
    assert parsers.url_for(PortFinding(host="[2001:db8::5]", port=80, service="http")) == "http://[2001:db8::5]"
    assert parsers.url_for(PortFinding(host="web (10.10.20.5)", port=443, service="ssl/http")) == "https://10.10.20.5"
    assert parsers.url_for(PortFinding(host="10.10.20.5", port=8080, service="http"), "lab.example.edu") == \
        "http://lab.example.edu:8080"
    assert parsers.url_for(PortFinding(host="10.10.20.5", port=443, service="https"), "2001:db8::9") == \
        "https://[2001:db8::9]"
    assert parsers.url_for(PortFinding(host="10.10.20.5", port=443, service=""), "") == "https://10.10.20.5"
    assert parsers.host_address("name (2001:db8::5)") == "2001:db8::5"
    assert parsers.host_address("name (1.2.3.4)  ") == "1.2.3.4" and parsers.host_address("2001:db8::5") == "2001:db8::5"


# --- WhatWeb parser -------------------------------------------------------------------------------

def whatweb(text: str):
    """Parse WhatWeb output for the standard probe of http://10.10.20.5."""
    return parsers.parse_whatweb_json(text, "http://10.10.20.5", "10.10.20.5", 80)


def test_whatweb_parser_collects_technologies_and_joins_version_lists():
    """Every plugin becomes a technology with its versions joined; Title is metadata and connection plugins are skipped."""
    finding = whatweb(json.dumps([{"target": "http://10.10.20.5", "http_status": 200, "plugins": {
        "HTTPServer": {"string": ["nginx/1.24.0"]}, "PHP": {"version": ["8.2.1", "8.2.2"]},
        "Title": {"string": ["Lab portal"]}, "jQuery": {"version": ["3.6.0"], "string": ["bundled"]},
        "IP": {"string": ["10.10.20.5"]}, "Country": {"string": ["RESERVED"]},
        "RedirectLocation": {"string": ["/x"]}, "UncommonHeaders": {"string": ["x-a"]},
        "Cookies": {"string": ["sid"]}}}]))
    assert finding.technologies == [
        {"name": "HTTPServer", "string": "nginx/1.24.0"}, {"name": "PHP", "version": "8.2.1, 8.2.2"},
        {"name": "jQuery", "version": "3.6.0", "string": "bundled"}, {"name": "Cookies", "string": "sid"},
    ]
    assert (finding.title, finding.status_code, finding.reachable, finding.final_url) == ("Lab portal", 200, True, None)
    assert (finding.url, finding.host, finding.port) == ("http://10.10.20.5", "10.10.20.5", 80)


def test_whatweb_parser_marks_empty_or_unparseable_output_unreachable():
    """An empty array, text that is not JSON, or a bare number means WhatWeb saw no HTTP response at all."""
    for text in ("[]", "this is not json {", "42", "null"):
        finding = whatweb(text)
        assert finding.reachable is False, text
        assert (finding.technologies, finding.status_code, finding.title, finding.final_url) == ([], None, None, None)


def test_whatweb_parser_reads_one_object_per_line_and_deduplicates_redirect_hops():
    """Line-oriented output with trailing commas is read; a plugin repeated by every hop is reported once."""
    finding = whatweb('{"target":"http://10.10.20.5","http_status":301,"plugins":{"HTTPServer":{"string":["nginx"]}}},\n'
                      '{"target":"http://10.10.20.5/home","http_status":200,"plugins":{"HTTPServer":{"string":["nginx"]},'
                      '"Title":{"string":["Home"]}}}\n'
                      'junk line that is not JSON\n')
    assert finding.reachable is True and finding.status_code == 200 and finding.title == "Home"
    assert finding.technologies == [{"name": "HTTPServer", "string": "nginx"}]
    assert finding.final_url == "http://10.10.20.5/home"
    two_versions = whatweb(json.dumps([{"plugins": {"PHP": {"version": ["7.4"]}}}, {"plugins": {"PHP": {"version": ["8.0"]}}}]))
    assert two_versions.technologies == [{"name": "PHP", "version": "7.4"}, {"name": "PHP", "version": "8.0"}]


def test_whatweb_parser_keeps_the_last_real_status_and_final_url_only_when_it_differs():
    """The status comes from the last hop that had one (0 and booleans do not count); a same-URL target is not a redirect."""
    assert whatweb(json.dumps([{"http_status": 200}, {"http_status": 0}])).status_code == 200
    assert whatweb(json.dumps([{"http_status": True}])).status_code is None
    assert whatweb(json.dumps([{"target": "http://10.10.20.5/", "plugins": {}}])).final_url is None
    assert whatweb(json.dumps({"target": "http://10.10.20.5", "http_status": 200, "plugins": {}})).reachable is True
    long_string = whatweb(json.dumps([{"plugins": {"X": {"string": ["a" * 500]}}}])).technologies[0]["string"]
    assert len(long_string) == 200  # descriptive strings are capped so a banner cannot bloat the report


# --- Nikto parser ---------------------------------------------------------------------------------

def test_classify_nikto_matches_keywords_as_whole_words():
    """Severity keywords match whole words only, so a longer word that merely contains one is not upgraded."""
    cases = [
        ("Tomcat Manager found", "high"),  # the keyword as a whole word
        ("Read the man page", "info"),  # "man" is not "manager"
        ("Managerial note", "info"),  # "manager" inside a longer word does not count
        ("admin2", "info"),  # a digit glued to the keyword
        ("admin_panel", "high"),  # an underscore is a word boundary
        ("/.git/HEAD found", "high"),
        ("/.github/ found", "info"),  # ".git" inside ".github"
        ("TRACE method is active", "medium"),
        ("traceroute enabled", "info"),
        ("/config.php found", "high"),
        ("Two backdoors found", "critical"),  # a plural "s" still counts as the keyword
        ("Several admins listed", "high"),
        ("Shellshock vulnerability", "critical"),  # a keyword of its own, not matched through "shell"
        ("/phpmyadmin/ found", "high"),
        ("/index.php?page=http://cirt.net/rfiinc.txt? RFI test", "critical"),
        ("/administrator/: This might be interesting.", "high"),  # the long form of "admin" (Joomla)
        ("Configuration information may be available remotely.", "high"),  # Nikto's wording for /config/
        ("Files may be uploaded to the server", "high"),  # "uploaded" is the long form of "upload"
    ]
    for message, severity in cases:
        assert parsers.classify_nikto(message) == severity, message


def test_classify_nikto_takes_the_most_severe_tier_and_defaults_to_info():
    """When several keywords appear the highest tier wins; a message with no keyword is "info"."""
    assert parsers.classify_nikto("Outdated nginx; admin panel") == "high"  # high beats medium
    assert parsers.classify_nikto("password in /rce") == "critical"  # critical beats high
    assert parsers.classify_nikto("Remote Code Execution") == "critical"
    assert parsers.classify_nikto("SQL Injection in id") == "critical"
    assert parsers.classify_nikto("phpinfo() output found") == "high"
    assert parsers.classify_nikto("Default credentials admin:admin") == "high"
    assert parsers.classify_nikto("The anti-clickjacking X-Frame-Options header is not present.") == "medium"
    assert parsers.classify_nikto("cookie without HttpOnly") == "medium"
    assert parsers.classify_nikto("X-Content-Type-Options header missing") == "low"
    assert parsers.classify_nikto("Retrieved x-powered-by header: PHP/7.4") == "low"
    assert parsers.classify_nikto("Server leaks inode 12345 via ETag") == "low"
    assert parsers.classify_nikto("Uncommon header found") == "info" and parsers.classify_nikto("") == "info"


@pytest.mark.parametrize("base,path,expected", [
    ("http://10.10.20.5", "/a", "http://10.10.20.5/a"),
    ("http://10.10.20.5/", "/a", "http://10.10.20.5/a"),  # no double slash
    ("http://10.10.20.5/", "a", "http://10.10.20.5/a"),  # no missing slash
    ("http://10.10.20.5:8080", "/x", "http://10.10.20.5:8080/x"),  # port kept
    ("http://[2001:db8::5]:8080", "/x", "http://[2001:db8::5]:8080/x"),  # IPv6 base kept intact
    ("http://10.10.20.5", "?q=1", "http://10.10.20.5/?q=1"),
    ("http://10.10.20.5", "ftp://other.lab.example.edu/y", "ftp://other.lab.example.edu/y"),  # absolute URL kept
    ("http://10.10.20.5", "/index.php?page=http://cirt.net/rfiinc.txt?",  # "://" inside a path is still a path
     "http://10.10.20.5/index.php?page=http://cirt.net/rfiinc.txt?"),
    ("http://10.10.20.5/", "", "http://10.10.20.5/"),  # no path: the scanned URL as given
])
def test_finding_url_joins_nikto_paths_onto_the_scanned_url(base, path, expected):
    """Nikto's url field is a path on the scanned URL, joined with exactly one slash and the port preserved."""
    assert parsers._finding_url(base, path) == expected


def test_nikto_json_reference_prefers_references_over_id_and_skips_blank_messages():
    """The reference is Nikto's references field, else its id; messages are trimmed and blank ones dropped."""
    findings = parsers.parse_nikto_json(json.dumps([{"host": "10.10.20.5", "vulnerabilities": [
        {"id": "999", "references": "https://cwe.example/1", "msg": "  Admin console  ", "url": "/admin"},
        {"id": "123", "msg": "No refs"}, {"msg": "   "}, {"msg": None},
        {"id": "5", "references": "", "msg": "empty refs"}]}]), "http://10.10.20.5")
    assert [(v.description, v.reference, v.url, v.severity) for v in findings] == [
        ("Admin console", "https://cwe.example/1", "http://10.10.20.5/admin", "high"),
        ("No refs", "123", "http://10.10.20.5", "info"),
        ("empty refs", "5", "http://10.10.20.5", "info"),
    ]


def test_nikto_json_accepts_one_host_object_and_an_empty_report():
    """A single host object (not wrapped in a list) is read; a host without findings yields none."""
    single = parsers.parse_nikto_json(json.dumps({"host": "h", "vulnerabilities": [{"msg": "A"}]}), "http://10.10.20.5")
    assert [v.description for v in single] == ["A"]
    assert parsers.parse_nikto_json('[{"host":"h","vulnerabilities":[]}]', "http://10.10.20.5") == []
    assert parsers.parse_nikto_json("   ", "http://10.10.20.5") == []


def test_nikto_text_fallback_skips_banners_and_statistics():
    """Non-JSON output is read line by line: only "+ " lines that are findings survive, banners and counters do not."""
    text = ("- Nikto v2.5.0\n+ Target IP: 10.10.20.5\n+ Target Hostname: h\n+ Start Time: 2024\n+ Server: nginx\n"
            "+ /admin/: Admin login page found.\n+ Retrieved x-powered-by header: PHP\n+ 7000 requests: 0 error(s)\n"
            "+ End Time: x\n+ 1 host(s) tested\n+ No CGI Directories found\n+ ERROR: boom\n+ Scan terminated: 0 error(s)\n"
            "+ Multiple IPs found\n  + indented finding\n- not a plus line\n+ Nikto v2 banner\n")
    assert not parsers.nikto_output_is_json(text) and parsers.nikto_output_is_json("[]")
    findings = parsers.parse_nikto_json(text, "http://10.10.20.5")  # hands non-JSON to the text parser
    assert [v.description for v in findings] == ["/admin/: Admin login page found.",
                                                 "Retrieved x-powered-by header: PHP", "indented finding"]
    assert [v.severity for v in findings] == ["high", "low", "info"]
    assert all(v.url == "http://10.10.20.5" for v in findings)
    # The header Nikto prints for an HTTPS port before any test runs ("+ SSL Info:" and its indented lines) is not a
    # finding either: Nikto killed right after it has examined nothing, as for an HTTP port (issue 9).
    https_header = ("- Nikto v2.5.0\n+ Target IP:          10.10.20.5\n+ Target Hostname:    10.10.20.5\n"
                    "+ Target Port:        443\n+ SSL Info:        Subject:  /CN=lab.example.edu\n"
                    "                   Ciphers:  TLS_AES_256_GCM_SHA384\n"
                    "                   Issuer:   /CN=lab.example.edu\n"
                    "+ Virtual Host:      lab.example.edu\n+ Start Time:         2026-11-12 10:00:00 (GMT3)\n")
    assert parsers.parse_nikto_json(https_header, "https://10.10.20.5") == []
    after_header = parsers.parse_nikto_text(https_header + "+ /admin/: Admin login page found.\n", "https://10.10.20.5")
    assert [v.description for v in after_header] == ["/admin/: Admin login page found."]


# --- Tool registry --------------------------------------------------------------------------------

def test_tool_catalogue_is_consistent_with_the_pipeline():
    """The default workflow is Nmap + WhatWeb, every tool knows its stage, and stages follow pipeline order."""
    assert registry.DEFAULT_TOOLS == ("nmap", "whatweb")
    assert set(registry.DEFAULT_TOOLS) <= set(registry.TOOLS)
    for name, spec in registry.TOOLS.items():
        assert spec.name == name and spec.stage in registry.STAGE_ORDER
        assert spec.binaries and spec.version_args and spec.install_hint and spec.description
    stage_positions = [registry.STAGE_ORDER.index(registry.TOOLS[n].stage) for n in ("nmap", "whatweb", "nikto")]
    assert stage_positions == sorted(stage_positions)
    assert "nikto.pl" in registry.TOOLS["nikto"].binaries  # the Perl script name some packages install
    # Custom tools (tools/custom.py) never shadow, wrap or extend the catalogue: their stage is not a pipeline stage,
    # and a definition that would run a shell, an interpreter, a script, an attack tool or a built-in scanner, point
    # the tool at a host of its own or store a secret is refused with a message that says why.
    assert custom.CUSTOM_STAGE not in registry.STAGE_ORDER and not set(custom.DEFAULT_PROGRAMS) & set(registry.TOOLS)
    allowed = custom.allowed_programs(["curl", "whois", "SSLSCAN.exe"])
    assert allowed == {"curl", "whois", "sslscan"} and custom.allowed_programs([" "]) == set(custom.DEFAULT_PROGRAMS)
    now = datetime.now(timezone.utc)

    def check(**fields):
        body = {"name": "hdrcheck", "program": "curl", "args": ["-sI", "{url}"], "scope": "url", **fields}
        return custom.validate_definition(CustomToolCreate(**body), allowed, now, look_up=False)

    tool = check(name=" HdrCheck ", description=" Header\n check ")
    assert (tool.name, tool.description, tool.args) == ("hdrcheck", "Header check", ["-sI", "{url}"])
    assert check(program="whois", args=["{target}"], scope="target").scope == "target"
    b64_key = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg=="  # a key in base64, with its padding
    refused = {
        "Name: use": [{"name": "1scan"}, {"name": "a b"}],
        "is a built-in tool": [{"name": "Nmap"}],
        "reserved by the dashboard": [{"name": "constructor"}],
        # Line breaks in a description are joined; an invisible character (a zero-width joiner) is what is refused.
        "remove invisible or control characters (for example a zero-width joiner)": [
            {"description": "Header\u200dcheck"}, {"description": "bell\x07"}],
        "shell, interpreter or launcher": [{"program": "bash"}, {"program": "powershell.exe"},
                                           {"program": "python3.12"}, {"program": "wsl"}, {"program": "pyw"},
                                           {"program": "ld-linux-x86-64.so.2"},
                                           # launchers, code runners and remote shells, also with a version or .exe
                                           {"program": "winrs"}, {"program": "psexec.exe"}, {"program": "jrunscript"},
                                           {"program": "Rscript"}, {"program": "julia"}, {"program": "sqlite3"},
                                           {"program": "proxychains4"}, {"program": "dotenv"}, {"program": "uvicorn"},
                                           {"program": "watchfiles"}, {"program": "linux64"}, {"program": "npx"},
                                           # database, file-transfer and code consoles, a debugger and an elevation
                                           # tool (R is compared as r, also as R.exe)
                                           *({"program": name} for name in (
                                               "R", "R.exe", "ntsd", "sftp", "regsvcs", "psql", "mysql", "mongosh",
                                               "mongo", "groovy", "scala", "gsudo", "elixir", "erl", "iex", "octave",
                                               "gnuplot", "ts-node", "tsx", "sqlcmd", "sqlplus"))],
        "is a script file": [{"program": "scan.sh"}, {"program": "nikto.pl"}, {"program": "scan.bat"}],
        "exploitation": [{"program": "sqlmap"}, {"program": "nuclei"}, {"program": "wapiti"},
                         {"program": "aircrack-ng"}],
        "is built in": [{"program": "nmap"}],
        "not on the list of allowed programs": [{"program": "dig"}],
        "a relative path": [{"program": "./curl"}, {"program": "-x"}, {"program": "\\\\host\\share\\curl.exe"}],
        # Every way of naming another host is refused: an address with a port, in brackets, after @, %-escaped (its
        # brackets too) or in a network path, also after the one slash of a URL such as http:/10.0.0.1.
        "fixed address or URL": [{"args": ["10.0.0.0/8", "{url}"]}, {"args": ["--host=10.0.0.1", "{url}"]},
                                 {"args": ["http://evil.example", "{url}"]}, {"args": ["10.0.0.1:8080", "{url}"]},
                                 {"args": ["[::1]:80", "{url}"]}, {"args": ["{url}@10.0.0.1"]},
                                 {"args": ["{url}", "10%2e0%2e0%2e1"]}, {"args": ["-T", "\\\\10.0.0.1\\s\\x", "{url}"]},
                                 {"args": ["{url}", "http:/10.0.0.1"]}, {"args": ["{url}", "%5B::1%5D:80"]}],
        # The host of a URL whose scheme has one slash (or a backslash, or %2F) is a host name like any other, and a
        # %-escaped host name is read decoded, as the tools read it.
        "looks like a host name": [{"args": ["{url}", "evil.example"]}, {"args": ["{url}", "evil.example?x"]},
                                   {"args": ["{url}", "evil.example#x"]}, {"args": ["{url}", "evil%2eexample"]},
                                   {"args": ["{url}", "localhost"]}, {"args": ["{url}.evil.example"]},
                                   {"args": ["{url}", "%65vil.example"]}, {"args": ["{url}", "http:/evil.example"]},
                                   {"args": ["{url}", "https:/evil.example/x"]}, {"args": ["{url}", "http:/localhost"]},
                                   {"args": ["{url}", "HTTP:/evil.example"]},
                                   {"args": ["{url}", "http:\\evil.example"]},
                                   {"args": ["{url}", "http:%2Fevil.example"]}],
        "If it is a file name, write it with its folder, for example ./out.txt": [{"args": ["-o", "out.txt", "{url}"]}],
        "contains @, which names a server": [{"args": ["{url}@evil.example"]}, {"args": ["-d", "@body.txt", "{url}"]},
                                             {"args": ["@{target}", "{url}"]},  # @{target} is for dig only
                                             {"args": ["{url}", "\uff20evil"]}],  # a full-width @ is an @ too
        # Two slashes or backslashes where a path starts (the argument, a piece after = , : or @, the value glued to
        # a short option, also behind other option letters), and two backslashes anywhere, name a network share.
        "holds two slashes or backslashes in a row": [
            {"args": ["-T", "\\\\srv\\share\\x", "{url}"]}, {"args": ["-T", "//srv/share/x", "{url}"]},
            {"args": ["-T", "/\\srv\\share\\x", "{url}"]}, {"args": ["-T", "\\/srv/share/x", "{url}"]},
            {"args": ["-T//srv/share/x", "{url}"]}, {"args": ["-sT//srv/share/x", "{url}"]},
            {"args": ["-o//fs.corp.example/share/out", "{url}"]}, {"args": ["--output=//srv/share/out", "{url}"]},
            {"args": ["-o", "C:\\a\\\\b", "{url}"]}, {"args": ["{url}?next=//evil"]},
            {"args": ["-F", "x=<//srv/share/x", "{url}"]}, {"args": ["-F", "x=</\\srv\\share\\x", "{url}"]},
            {"args": ["-#T//srv/share/x", "{url}"]},
            {"program": "sslscan", "args": ["-o//srv/share/x", "{target}"], "scope": "target"}],
        # The NT prefix \??\ passes a path through unchanged, a network share (\??\UNC\srv) or a drive alike.
        "uses the \\??\\ prefix": [{"args": ["-T", "\\??\\UNC\\srv\\share\\x", "{url}"]},
                                  {"args": ["-o", "\\??\\C:\\out.html", "{url}"]}],
        "uses curl's [ ] ranges": [{"args": ["{url}", "10.0.0.[1-254]"]}, {"args": ["{url}/[1-100]"]}],
        "sends the tool's traffic through another host or reads options or targets from a file": [
            {"args": ["-K", "./opts", "{url}"]}, {"args": ["--config=./opts", "{url}"]},
            {"args": ["--conf", "./opts", "{url}"]}, {"args": ["-sK", "./opts", "{url}"]},
            {"args": ["-x", "proxyhost:3128", "{url}"]}, {"args": ["-sx", "proxyhost", "{url}"]},
            {"args": ["--proxy", "proxyhost", "{url}"]}, {"args": ["--connect-to", "::proxyhost:80", "{url}"]},
            {"args": ["--resolve", "x:80:y", "{url}"]},
            {"program": "whois", "args": ["-h", "srv", "{target}"], "scope": "target"},
            {"program": "whois", "args": ["-Hhsrv", "{target}"], "scope": "target"}],
        "not a placeholder": [{"args": ["{target.__class__}"]}, {"args": ["{URL}"]}],
        "without spaces": [{"args": ["a b", "{url}"]}, {"args": ["x\x00", "{url}"]}],
        "quotes are not supported": [{"args": ["'{url}'"]}],
        "brute-force, exploit": [{"args": ["--brute", "{url}"]}],
        "password, key or token": [{"args": ["--password=x", "{url}"]}, {"args": ["--key=" + "a1" * 20, "{url}"]},
                                   # base64 padding does not hide a key (issue 7)
                                   {"args": ["--key=" + "a1" * 20 + "==", "{url}"]}, {"args": [b64_key, "{url}"]},
                                   {"args": ["{url}?k=" + b64_key]}, {"args": ["-d", "x=" + b64_key[:-1], "{url}"]}],
        "passes a user name, password": [{"args": ["-u", "admin:pw", "{url}"]}, {"args": ["--user=admin:pw", "{url}"]},
                                         {"args": ["-su", "a:b", "{url}"]}, {"args": ["-uadmin:pw", "{url}"]},
                                         {"args": ["-b", "s=1", "{url}"]}, {"args": ["-E", "c.pem", "{url}"]}],
        "needs {url}": [{"args": ["{target}"]}],
        "needs {target}": [{"args": ["-v"], "scope": "target"}],
        "only filled in for a tool that runs once per web URL": [{"args": ["{url}"], "scope": "target"}],
    }
    for words, cases in refused.items():
        for fields in cases:
            with pytest.raises(custom.CustomToolError, match=re.escape(words)):
                check(**fields)
    # dig @server asks another name server; only dig @{target}, written exactly so, asks the target itself.
    with_dig = custom.allowed_programs(["curl", "dig"])

    def dig(*args):
        body = CustomToolCreate(name="dnscheck", program="dig", args=list(args), scope="target")
        return custom.validate_definition(body, with_dig, now, look_up=False)

    for args, words in ((["@10.0.0.53", "{target}"], "fixed address or URL"), (["@server", "{target}"], "contains @"),
                        (["@ns.example", "{target}"], "contains @"), (["@{target}x", "{target}"], "contains @"),
                        (["-f", "./names", "{target}"], "reads options or targets from a file")):
        with pytest.raises(custom.CustomToolError, match=re.escape(words)):
            dig(*args)
    assert dig("@{target}", "{target}").args == ["@{target}", "{target}"]
    # A placeholder with a port or a path, a file written with its folder (also on a drive), and options that only
    # change what the tool prints stay allowed; so do a header whose value is a path (X-Original-URL:/admin), the
    # %-escapes of a query, which curl sends as they are (%5B%5D is no range, %40 no user and %2F%2F no share), and
    # two slashes inside a path.
    assert check(args=["{target}:443"], scope="target").args == ["{target}:443"]
    for args in (["{url}/robots.txt"], ["-o", "./out.txt", "{url}"], ["-sI", "--max-time", "20", "{url}"],
                 ["-H", "Accept:text/html", "{url}"], ["-H", "X-Original-URL:/admin", "{url}"],
                 ["-H", "X-Forwarded-Prefix:/api", "{url}"], ["-H", "Referer:/", "{url}"],
                 ["-o", "C:/out.html", "{url}"], ["--output=C:/out.html", "{url}"], ["{url}/?a%5B%5D=1"],
                 ["-d", "x=%5B%5D", "{url}"], ["{url}/?email=a%40b"], ["{url}/?next=%2F%2Fhome"], ["{url}/a//b"],
                 ["{url}//admin"], ["-o", "./a//b", "{url}"], ["-Tfoo//bar", "{url}"], ["-oC:/out.html", "{url}"],
                 ["-F", "x=<C:/notes.txt", "{url}"], ["-F", "x=y;headers=<C:\\h.txt", "{url}"]):
        assert check(args=args).args == args
    # For a program whose option letters are not known, a glued drive path reads as a host name; the message says
    # how to write it instead.
    with pytest.raises(custom.CustomToolError, match=re.escape("as an argument of its own (-O C:/page.html)")):
        custom.validate_definition(CustomToolCreate(name="getpage", program="wget", args=["-OC:/page.html", "{url}"],
                                                    scope="url"), custom.allowed_programs(["wget"]), now, look_up=False)
    # The long tail of code runners and launchers is refused by name too (round 5c).
    for program in ("parallel", "capsh", "unbuffer", "gmake", "cmake", "ocaml", "swipl", "R", "psql", "sftp",
                    "xdg-open", "smbclient", "lftp", "autossh", "wine64", "qemu-x86_64", "tcc", "m4", "gp"):
        assert "shell, interpreter or launcher" in (custom.program_problem(program) or "")
    # An allow-list entry written as a path allows only that file, compared as the real path in the system's letter
    # case, and a stored tool outside it is refused too; the name written alone allows the program from any folder.
    windows = os.name == "nt"
    only_file = "C:\\Tools\\curl.exe" if windows else "/opt/tools/curl"
    elsewhere = "D:\\Elsewhere\\curl.exe" if windows else "/srv/elsewhere/curl"
    pinned = custom.allowed_programs([only_file, "whois"])
    assert pinned == {"curl", "whois"} and dict(pinned.paths) == {"curl": (only_file,)}
    for bare in ("curl", "curl.exe"):  # a bare name is looked up on PATH when it runs, so it never matches a pin
        with pytest.raises(custom.CustomToolError, match="only as"):
            custom.validate_definition(CustomToolCreate(name="pinned", program=bare, args=["{url}"], scope="url"),
                                       pinned, now, look_up=False)
    two = custom.allowed_programs([only_file, elsewhere])
    with pytest.raises(custom.CustomToolError, match="one of those full paths"):
        custom.validate_definition(CustomToolCreate(name="pinned", program="curl", args=["{url}"], scope="url"),
                                   two, now, look_up=False)
    assert pinned.shown == (only_file, "whois") and dict(allowed.paths) == {}

    def register(program, allow=pinned):
        body = CustomToolCreate(name="hdrcheck", program=program, args=["-sI", "{url}"], scope="url")
        return custom.validate_definition(body, allow, now, look_up=False).program

    for program in ("curl", elsewhere):
        with pytest.raises(custom.CustomToolError, match=re.escape(f"allows curl only as {only_file}, so register")):
            register(program)
    # A relative path entry is read from the folder HybridSec was started from: that full path is shown and pinned.
    relative = os.path.join("tools", "curl.exe" if windows else "curl")
    from_here = custom.allowed_programs([relative])
    assert from_here.shown == (os.path.abspath(relative),) and dict(from_here.paths) == {"curl": from_here.shown}
    assert register(os.path.abspath(relative), from_here) == os.path.abspath(relative)
    spellings = [only_file, "c:/tools/curl.exe", "C:\\Tools\\..\\Tools\\CURL.EXE"] if windows else [only_file]
    assert [register(program) for program in spellings] == spellings
    outside = custom.CustomTool(name="hdrcheck", program=elsewhere, args=["-sI", "{url}"], scope="url", created_at=now)
    assert f"allows curl only as {only_file}" in custom.definition_problem(outside, pinned)
    assert register(elsewhere, custom.allowed_programs([only_file, "curl"])) == elsewhere
    # Only the placeholders are replaced, each argument stays one list item, and the output is plain text.
    assert custom.build_command("curl", ["-sI", "{url}", "x{target}y"], "10.0.0.5", "http://10.0.0.5:8080") == \
        ["curl", "-sI", "http://10.0.0.5:8080", "x10.0.0.5y"]
    assert custom.clean_output("\x1b[31mred\x1b[0m\r\nok\x07\tend") == "red\nok\tend"
    # The 8-bit (C1) control codes too: an 8-bit CSI, and an 8-bit OSC ended by the 8-bit ST, with its payload.
    assert custom.clean_output("ok\x9b2J\x9d52\x9c") == "ok"
    # Terminal control strings go whole, with what they carry (a window title, a hyperlink target, a DCS payload),
    # in their 7-bit and 8-bit forms and whatever ends them (BEL, ESC \ or the 8-bit ST), and so do the invisible
    # bidi and zero-width characters (issue 19), the word joiner and invisible operators (U+2060-U+2064), the
    # Mongolian vowel separator and the tag characters.
    assert custom.clean_output("\x1b]0;title\x07ok") == "ok"
    assert custom.clean_output("a\x1b]8;;http://x.example/\x1b\\link\x1b]8;;\x1b\\b") == "alinkb"
    assert custom.clean_output("\x1bPq#0;payload\x1b\\done \x9d0;title\x07x") == "done x"
    assert custom.clean_output("a\x1b]0;title\x9cb\x90dcs\x9cc\x98sos\x07d\x9epm\x1b\\e\x9fapc\x9cf") == "abcdef"
    assert custom.clean_output("\u202eevil\u202c z\u200bw\ufeff\u2066i\u2069\u200e\u061c") == "evil zwi"
    invisible = "a\u2060b\u2061c\u2062d\u2063e\u2064f\u180eg\U000e0001\U000e0041\U000e007fh"
    assert custom.clean_output(invisible) == "abcdefgh"
    # The zero-width non-joiner and joiner stay: Persian and Indic words and emoji sequences need them.
    persian = "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645"  # a Persian word with its non-joiner
    family = "\U0001f468\u200d\U0001f469\u200d\U0001f467"  # one emoji: three people joined by zero-width joiners
    assert custom.clean_output(f"{persian} {family}") == f"{persian} {family}"
    # A control string without an end is removed up to the end of its line, or up to the next ESC, which starts the
    # next code, so the lines and the text after it stay; and text full of introducers, which a target controls, is
    # still cleaned in linear time.
    assert custom.clean_output("line1\n\x1b]0;open\nline2\x07end") == "line1\n\nline2end"
    assert custom.clean_output("a\x1b]0;ti\ntle\x07b") == "a\ntleb"
    assert custom.clean_output("\x1b]0;t\x1b[31mred") == "red"
    started = time.perf_counter()
    assert custom.clean_output("\x9d" * 10_000 + "\x9dA\n" * 5_000 + "\x1b]" * 5_000) == "\n" * 5_000
    assert custom.clean_output("\x1b]" + "x" * 100_000 + "\n" + "\x9d" * 100_000 + "\x1b]\x07" * 20_000) == "\n"
    assert time.perf_counter() - started < 0.2
    # Options that only read (-sI, --max-time, --cert-status, -H Accept:x) stay allowed.
    assert check(args=["-sI", "--max-time", "20", "--cert-status", "-H", "Accept:x", "{url}"]).args[0] == "-sI"
    # The file that is checked is the file that runs: a link to an interpreter, a special file, a file in HybridSec's
    # own folder (Windows looks there first), a script, or a program on a network share is refused.
    from unittest import mock
    with mock.patch.object(custom.shutil, "which", return_value=sys.executable):  # e.g. sslscan -> python3.12
        path, problem = custom.find_program("sslscan")
        assert path is None and "resolves to" in problem and "shell, interpreter or launcher" in problem
        with pytest.raises(custom.CustomToolError, match="resolves to"):
            custom.validate_definition(CustomToolCreate(name="tlsscan", program="sslscan", args=["{target}"],
                                                        scope="target"), allowed, now)  # look_up=True
        info = custom.tool_info(custom.CustomTool(name="tlsscan", program="sslscan", args=["{target}"],
                                                  scope="target", created_at=now), allowed, True)
        assert info.installed is False and info.path is None and "interpreter" in info.install_hint
        # Found but refused is its own state, not "not installed"; the definition itself still passes (issue 22).
        assert info.blocked is True and info.refused is False
    tlsscan = custom.CustomTool(name="tlsscan", program="sslscan", args=["{target}"], scope="target", created_at=now)
    with mock.patch.object(custom.shutil, "which", return_value=None):
        missing = custom.tool_info(tlsscan, allowed, True)
    assert (missing.installed, missing.blocked, missing.refused) == (False, False, False)
    assert "was not found on this machine" in missing.install_hint
    unlisted = custom.tool_info(tlsscan.model_copy(update={"program": "dig"}), allowed, True)
    assert (unlisted.installed, unlisted.blocked, unlisted.refused) == (False, False, True)
    # A stored row whose name registration would have written another way (edited by hand) is refused with a reason.
    assert "is not written the way registration stores names" in custom.definition_problem(
        tlsscan.model_copy(update={"name": "TLSScan"}), allowed)
    # Nothing inside HybridSec's own folder (its .venv included) may run, and a launcher is refused by the file it
    # resolves to, whatever name it was registered under (issue 6).
    venv_program = os.path.join(custom._BASE_DIR, ".venv", *(("Scripts", "sslscan.exe") if os.name == "nt" else
                                                              ("bin", "sslscan")))
    with mock.patch.object(custom.shutil, "which", return_value=venv_program):
        assert "inside HybridSec's own folder (its .venv included)" in custom.find_program("sslscan")[1]
        assert custom.tool_info(tlsscan, allowed, True).blocked is True
    with mock.patch.object(custom.shutil, "which", return_value="C:\\Tools\\winrs.exe" if os.name == "nt" else
                           "/opt/tools/winrs"):
        problem = custom.find_program("sslscan")[1]
        assert "resolves to" in problem and "is a shell, interpreter or launcher" in problem
    # A long path in a message is cut in the middle, so the file name at its end stays visible (issue 22).
    long_path = "C:\\" + "very-long-folder-name\\" * 6 + "another-level\\dig.bat"
    cut = custom._cut_path(long_path)
    assert len(cut) == 80 and "..." in cut
    assert cut.startswith("C:\\very-long") and cut.endswith("another-level\\dig.bat")
    if os.name == "nt":
        # A program found in the folder HybridSec was started from (outside its own folder) is refused by name.
        with mock.patch.object(custom.os, "getcwd", return_value="C:\\elsewhere"), \
                mock.patch.object(custom.shutil, "which", return_value="C:\\elsewhere\\sslscan.exe"), \
                mock.patch.object(custom.os.path, "realpath", side_effect=lambda p: p):
            assert "was found in the folder HybridSec was started from" in custom.find_program("sslscan")[1]
        with mock.patch.object(custom.shutil, "which", return_value="C:\\tools\\sslscan.cmd"):
            assert "not an .exe or .com file" in custom.find_program("C:\\tools\\sslscan.cmd")[1]
        with mock.patch.object(custom.shutil, "which", return_value=long_path):
            assert "another-level\\dig.bat is not an .exe or .com file" in custom.find_program("dig")[1]
        with mock.patch.object(custom.shutil, "which", return_value="\\\\server\\share\\sslscan.exe"), \
                mock.patch.object(custom.os.path, "realpath", side_effect=lambda p: p):
            assert "network share" in custom.find_program("sslscan")[1]
    else:
        with mock.patch.object(custom.shutil, "which", return_value="/dev/null"):
            assert "special system file" in custom.find_program("sslscan")[1]


def test_unknown_tools_reports_unsupported_names_in_their_original_spelling():
    """The error the operator sees quotes exactly what they typed; known tools pass in any case or spacing."""
    assert registry.unknown_tools(["NMAP", "metasploit", " nikto ", "", "nmap.exe", "n map"]) == \
        ["metasploit", "", "nmap.exe", "n map"]
    assert registry.unknown_tools(["alpha", " Alpha ", "beta"], custom={"alpha"}) == ["beta"]  # registered custom tools


def test_known_tool_ignores_case_and_surrounding_whitespace():
    """known_tool() and order_tools() agree: surrounding whitespace and letter case never make a tool unknown."""
    for name in (" NMAP ", "nmap\t", "Nikto", "whatweb\n"):
        assert registry.known_tool(name) is True and registry.order_tools([name]) != [], repr(name)
    for name in ("n map", "", "nmap.exe", "zap"):
        assert registry.known_tool(name) is False and registry.order_tools([name]) == [], repr(name)


def test_order_tools_sorts_into_pipeline_order_and_drops_duplicates_and_unknowns():
    """Whatever order the operator picks, nmap runs first; repeated and unknown names disappear."""
    assert registry.order_tools(["nikto", "whatweb", "nmap", "NMAP", "zap", " Nikto"]) == ["nmap", "whatweb", "nikto"]
    assert registry.order_tools(["whatweb"]) == ["whatweb"]
    assert registry.order_tools([]) == []
    # Registered custom tools run after the built-in tools, in alphabetical order; unregistered ones are unknown.
    assert registry.order_tools(["zeta", "Nikto", "alpha", "nmap", " ZETA "], custom={"alpha", "zeta"}) == \
        ["nmap", "nikto", "alpha", "zeta"]
    assert registry.order_tools(["alpha"]) == []


def test_version_regexes_extract_the_version_from_each_tools_banner():
    """Each tool's version pattern finds the version number in the banner its --version command prints."""
    banners = [
        ("nmap", "Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu", "7.95"),
        ("whatweb", "WhatWeb version 0.5.5-dev ( https://www.morningstarsecurity.com/research/whatweb/ )", "0.5.5-dev"),
        ("nikto", "- Nikto v2.5.0\n---------------", "2.5.0"),
        ("nikto", "Nikto 2.1.6", "2.1.6"),
    ]
    for tool, banner, version in banners:
        match = re.search(registry.TOOLS[tool].version_regex, banner)
        assert match is not None and match.group(1) == version, (tool, banner)


def test_missing_tools_are_reported_as_not_installed_without_starting_anything(monkeypatch):
    """A tool that is not on PATH gives installed=False with its install hint; no process is started to find out."""
    real_detect_version = registry.detect_version.__wrapped__  # the function behind the lru_cache
    monkeypatch.setattr(registry.shutil, "which", lambda name: None)
    monkeypatch.setattr(registry, "detect_version", lambda *args: pytest.fail("detect_version must not run"))
    assert registry.availability() == {"nmap": False, "whatweb": False, "nikto": False}
    for info in registry.list_tools():
        assert (info.installed, info.path, info.version) == (False, None, None) and info.install_hint
    # The executables are tried in order of preference: the second name is found when the first is missing.
    monkeypatch.setattr(registry.shutil, "which", lambda name: "/opt/nikto/nikto.pl" if name == "nikto.pl" else None)
    assert registry.resolve_binary(registry.TOOLS["nikto"]) == "/opt/nikto/nikto.pl"
    # Asking a binary that cannot start for its version is not an error either.
    assert real_detect_version(r"D:\no\such\dir\hybridsec-missing-tool.exe", ("--version",), "x") is None


# --- Subprocess runner ----------------------------------------------------------------------------

class FakePopen:
    """Stands in for subprocess.Popen so the runner's call can be inspected without starting a process."""

    calls: ClassVar[list[FakePopen]] = []

    def __init__(self, *args, **kwargs):
        self.args, self.kwargs, self.communicate_timeout = args, kwargs, None
        self.returncode = 0
        FakePopen.calls.append(self)

    def communicate(self, timeout=None):
        self.communicate_timeout = timeout
        return "out", "err"

    def kill(self):
        pass


@pytest.fixture(autouse=True, scope="module")
def scanners_may_start():
    """Re-arm the runner the way the app's startup does: an earlier test module's shutdown blocks new processes."""
    runner.accept_new_processes()


@pytest.fixture
def fake_popen(monkeypatch):
    """Route runner.run_command() to FakePopen for one test and hand back the recorded calls."""
    FakePopen.calls = []
    monkeypatch.setattr(runner.subprocess, "Popen", FakePopen)
    return FakePopen.calls


def test_terminate_all_blocks_new_processes_until_startup_re_arms_the_runner(fake_popen):
    """Once shutdown has begun no scanner may start (a worker must not launch the next one); startup re-arms it."""
    try:
        assert runner.terminate_all() == 0
        with pytest.raises(OSError, match="shutting down"):
            run_command(["nmap", "--version"], timeout=5)
        assert fake_popen == []  # nothing was started
        runner.accept_new_processes()
        assert run_command(["nmap", "--version"], timeout=5).exit_code == 0 and len(fake_popen) == 1
    finally:
        runner.accept_new_processes()


def test_run_command_passes_the_argument_list_without_a_shell(fake_popen):
    """The command is an argument list handed to the OS directly: shell=False, so metacharacters are never interpreted."""
    command = ["nmap", "-sS", "10.10.20.5;id"]
    result = run_command(command, timeout=5)
    assert len(fake_popen) == 1
    assert fake_popen[0].args == (command,) and fake_popen[0].kwargs["shell"] is False
    assert result.command == command and result.exit_code == 0 and result.stdout == "out" and result.stderr == "err"


def test_run_command_closes_stdin_and_captures_both_streams_as_text(fake_popen):
    """A tool that asks a question reads end-of-file instead of hanging; output is captured as text, bad bytes replaced."""
    run_command(["nmap", "--version"], timeout=5)
    kwargs = fake_popen[0].kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE and kwargs["stderr"] is subprocess.PIPE
    assert kwargs["text"] is True and kwargs["errors"] == "replace"


def test_run_command_waits_at_least_one_second(fake_popen):
    """Timeouts below one second are raised to one second so a tool always gets a chance to start."""
    run_command(["nmap"], timeout=0.2)
    run_command(["nmap"], timeout=7.5)
    assert [call.communicate_timeout for call in fake_popen] == [1.0, 7.5]


def test_run_command_rejects_empty_or_non_string_commands(fake_popen):
    """A command must be a non-empty list of strings; anything else is refused before any process starts."""
    for bad in ([], ["nmap", 5], ["nmap", None], [b"nmap"]):
        with pytest.raises(ValueError, match="non-empty list of strings"):
            run_command(bad, timeout=5)
    assert fake_popen == []


def test_run_command_rejects_a_bare_string_command(fake_popen):
    """A command line given as one string is not an argument list and must be refused like any other wrong type."""
    with pytest.raises(ValueError):
        run_command("nmap -sS 10.10.20.5", timeout=5)


def test_run_command_returns_exit_code_and_output_of_a_real_process():
    """A non-zero exit does not raise: the exit code, stdout and stderr are returned for the caller to inspect."""
    result = run_command([sys.executable, "-c", "import sys; print('hello'); sys.stderr.write('warn'); sys.exit(3)"],
                         timeout=20)
    assert result.exit_code == 3 and result.timed_out is False
    assert result.stdout == "hello\n" and result.stderr == "warn"
    assert result.duration_seconds >= 0 and result.command[0] == sys.executable
    assert runner._live == set()  # nothing stays tracked after the process has ended


def test_run_command_kills_the_process_at_the_timeout_and_keeps_partial_output():
    """At the time limit the process is killed, timed_out is set, exit_code is None and what it printed is kept.
    The process here is a wrapper, like nikto.bat or a shell script: the real work is a grandchild that holds the
    output pipe. The whole process tree is killed, so the limit holds instead of waiting the grandchild's 30
    seconds out."""
    wrapper = ("import subprocess, sys, time; "
               "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], stdout=sys.stdout, "
               "stderr=sys.stderr); print('partial', flush=True); time.sleep(30)")
    started = time.monotonic()
    result = run_command([sys.executable, "-c", wrapper], timeout=0.2)  # raised to the one-second minimum
    assert result.timed_out is True and result.exit_code is None
    assert result.stdout.startswith("partial")
    assert 0.9 <= result.duration_seconds < 5 and time.monotonic() - started < 10
    assert runner._live == set()
    # With max_chars (custom tools) the limit holds while the output is read: a process that keeps printing is
    # stopped as soon as it passes the limit, instead of being waited for.
    started = time.monotonic()
    flood = run_command([sys.executable, "-c", "import sys, time; sys.stdout.write('x' * 200000); sys.stdout.flush(); "
                         "time.sleep(30)"], timeout=20, max_chars=1000)
    assert flood.stdout == "x" * 1000 and flood.truncated is True and flood.timed_out is False
    assert time.monotonic() - started < 15 and runner._live == set()
    quiet = run_command([sys.executable, "-c", "print('ok')"], timeout=20, max_chars=1000)
    assert quiet.stdout.strip() == "ok" and quiet.truncated is False and quiet.exit_code == 0
    # The read-limited path keeps the time limit as well: the wrapper and its grandchild are stopped together.
    capped = run_command([sys.executable, "-c", wrapper], timeout=0.2, max_chars=1000)
    assert capped.timed_out is True and capped.exit_code is None and capped.stdout.startswith("partial")
    assert capped.duration_seconds < 5 and runner._live == set()
    if os.name != "nt":  # a wrapper that exits at once, leaving its helper running in the process group
        early = ("import subprocess, sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
                 "stdout=sys.stdout, stderr=sys.stderr); print('started', flush=True)")
        started = time.monotonic()
        left = run_command([sys.executable, "-c", early], timeout=1, max_chars=1000)
        assert left.stdout.startswith("started") and left.timed_out is True and time.monotonic() - started < 5


def test_running_processes_are_tracked_and_terminate_all_kills_them():
    """A process is tracked while it runs; terminate_all() kills it, the child exits and nothing stays tracked."""
    outcome = {}
    worker = threading.Thread(
        target=lambda: outcome.update(result=run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=20)))
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not runner._live:
            time.sleep(0.01)
        assert len(runner._live) == 1
        child = next(iter(runner._live))
        assert child.poll() is None  # still running
        assert runner.terminate_all() == 1
        worker.join(timeout=5)
        assert not worker.is_alive() and child.poll() is not None  # the child really exited
        assert outcome["result"].exit_code != 0 and outcome["result"].timed_out is False  # killed, not timed out
        assert runner._live == set() and runner.terminate_all() == 0
    finally:
        runner.accept_new_processes()  # terminate_all() also blocks new processes; re-arm as startup would
        worker.join(timeout=5)


def test_output_is_capped_at_max_output_chars(monkeypatch):
    """Both output streams are truncated to MAX_OUTPUT_CHARS so a chatty tool cannot exhaust memory."""
    monkeypatch.setattr(runner, "MAX_OUTPUT_CHARS", 10)
    result = run_command([sys.executable, "-c", "import sys; print('x' * 100); sys.stderr.write('y' * 100)"], timeout=20)
    assert result.stdout == "x" * 10 and result.stderr == "y" * 10
