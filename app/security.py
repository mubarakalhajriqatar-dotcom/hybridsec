"""Target validation and scope enforcement: nothing reaches a scanner subprocess without passing here.

normalize_target() accepts exactly one IP address, hostname or small CIDR block, and rejects anything a
scanner could read as an option, a list or a range. check_scope() then applies the optional allow-list
(HYBRIDSEC_ALLOWED_TARGETS). The execute endpoint calls both through validate_execution_target().
"""
from __future__ import annotations

import ipaddress
import re

from .config import settings

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# Shell metacharacters plus everything nmap could read as a target list or range: "," (lists),
# "*" (wildcards), "%" (IPv6 zone ids). Hyphen ranges are rejected separately in normalize_target().
_FORBIDDEN_CHARS = set(" \t\r\n;&|`$<>(){}'\"\\,*%!")
_NUMERIC_LABEL_RE = re.compile(r"^[0-9-]+$")
# The largest block one run may scan: a /24 is 256 IPv4 addresses, a /120 the same number of IPv6 addresses.
_MAX_PREFIX_LENGTH = {4: 24, 6: 120}


class TargetError(ValueError):
    """A target or allow-list entry was rejected. The message is shown to the operator as-is."""


# --- Scan targets ---------------------------------------------------------------------------------

def normalize_target(raw: str) -> str:
    """Return the canonical form of a single scan target, or raise TargetError.

    Accepts one IPv4/IPv6 address, one hostname, or one CIDR block no larger than /24 (IPv4) or /120
    (IPv6). Rejects anything that looks like a shell argument, URL, path or IPv6 zone id, and nmap
    range/list syntax (10.0-255.0.1, 10.0.0.*, a,b), because nmap would happily scan all of it.
    """
    target = (raw or "").strip()
    if not target:
        raise TargetError("Target is empty. Give an IP address, hostname or CIDR block.")
    if any(ch in _FORBIDDEN_CHARS for ch in target):
        raise TargetError("Target contains characters that are not allowed. "
                          "Give a single IP address, hostname or CIDR block.")
    if target.startswith("-"):
        # nmap would read "-sS ..." as an option rather than a target.
        raise TargetError("Target must not start with a dash.")
    if "://" in target or ("/" in target and not _looks_like_cidr(target)):
        raise TargetError("Give a host, IP or CIDR, not a URL or path.")

    if _looks_like_cidr(target):
        return _normalize_cidr(target)

    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass  # not an IP address, so it must be a hostname

    if _HOSTNAME_RE.match(target):
        hostname = target.lower()
        # "10.0-255.0-255.1" and "1-254" are nmap octet ranges that happen to fit the hostname syntax. Without a
        # hyphen, an all-numeric name is one address in a form ipaddress refuses and scanners may read differently:
        # a leading zero (127.0.0.01, octal to some), a short form (127.1) or a plain integer (2130706433).
        if all(_NUMERIC_LABEL_RE.match(label) for label in hostname.split(".")):
            if "-" in hostname:
                raise TargetError("Address ranges are not allowed. Give a single IP, a hostname or a CIDR up to /24.")
            raise TargetError(f"'{hostname}' is not a standard dotted IP address. Write it as four numbers from 0 to "
                              "255 without leading zeros, for example 127.0.0.1.")
        if not _has_alphabetic_tld(hostname):
            raise TargetError("Hostname must end in an alphabetic top-level label such as .com or .local.")
        return hostname
    raise TargetError("Target is not a valid IP address, hostname or CIDR.")


def _normalize_cidr(target: str) -> str:
    """Canonical form of a CIDR block (host bits cleared), refusing blocks larger than one run may scan.
    A block that holds a single address is returned as that address."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise TargetError(f"Invalid CIDR: {exc}.") from exc
    max_prefix = _MAX_PREFIX_LENGTH[network.version]
    if network.prefixlen < max_prefix:
        raise TargetError(f"CIDR too large. Use /{max_prefix} or smaller.")
    if network.num_addresses == 1:
        # A /32 or /128 is one host: "10.0.0.5/32" becomes "10.0.0.5", so the web stages build normal URLs.
        return str(network.network_address)
    return str(network)


def _looks_like_cidr(value: str) -> bool:
    """True for "<something>/<digits>"; whether the address part is valid is decided by the caller."""
    return "/" in value and value.rsplit("/", 1)[-1].isdigit()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _has_alphabetic_tld(hostname: str) -> bool:
    """Real top-level domains contain letters; "1.2.3.4.5" or "example.123" are typos, not hostnames."""
    return bool(re.search(r"[a-z]", hostname.rsplit(".", 1)[-1]))


# --- Allow-list (scope) ---------------------------------------------------------------------------

def validate_allowlist_entry(raw: str) -> str:
    """Normalise one HYBRIDSEC_ALLOWED_TARGETS entry: a host, an IP, a CIDR of any size, or a *.domain wildcard.

    Unlike a scan target, an entry may be a large CIDR: it limits what may be scanned and is never scanned
    as a whole itself.
    """
    entry = (raw or "").strip().lower()
    if not entry:
        raise TargetError("Empty allow-list entry.")
    if entry.startswith("*."):
        suffix = entry[2:]
        if not _HOSTNAME_RE.match(suffix) or not _has_alphabetic_tld(suffix):
            raise TargetError(f"Invalid wildcard pattern '{raw}': use *.example.com with an alphabetic domain.")
        return entry
    if _looks_like_cidr(entry):
        try:
            return str(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise TargetError(f"Invalid CIDR '{raw}': {exc}.") from exc
    return normalize_target(entry)


def matches_allowlist_entry(target: str, allowed: str) -> bool:
    """True when a normalised target falls inside one allow-list entry.

    An entry matches when it is the same host or IP, when it is a CIDR that contains the target (for a
    CIDR target, the whole block must fit inside), or when it is a *.domain wildcard and the target is a
    subdomain. Wildcards never match the bare domain or any IP address, so "*.1.2.3" cannot be used to
    allow 10.1.2.3.
    """
    allowed = allowed.strip().lower()
    if target == allowed:
        return True
    if allowed.startswith("*."):
        if _is_ip(target) or "/" in target:
            return False
        return target.endswith(allowed[1:]) and target != allowed[2:]
    try:
        network = ipaddress.ip_network(allowed, strict=False)
    except ValueError:
        return False  # a hostname entry, and the exact comparison above did not match
    try:
        if "/" in target:
            return ipaddress.ip_network(target, strict=False).subnet_of(network)
        return ipaddress.ip_address(target) in network
    except (ValueError, TypeError):
        return False  # a hostname target, or an IPv4 target checked against an IPv6 entry


def check_scope(target: str) -> None:
    """Raise TargetError unless the target matches an allow-list entry. An empty allow-list allows everything."""
    if not settings.allowed_targets:
        return
    if any(matches_allowlist_entry(target, allowed) for allowed in settings.allowed_targets):
        return
    raise TargetError(
        f"'{target}' is outside the allowed scope. Allowed: {', '.join(settings.allowed_targets)}. "
        "Choose a target inside the scope or extend the allow-list on the Settings page."
    )


def validate_execution_target(raw: str, authorized: bool) -> str:
    """Everything a target must pass before a run starts: the authorization flag, the syntax, then the scope.

    Returns the normalised target that the run will use.
    """
    if not authorized:
        raise TargetError(
            "Set 'authorized' to true to confirm you own this target or have written permission to test it."
        )
    target = normalize_target(raw)
    check_scope(target)
    return target


# --- Target properties ----------------------------------------------------------------------------

def is_ipv6_target(target: str) -> bool:
    """True for an IPv6 address or block; nmap needs its -6 flag to scan one."""
    try:
        return ipaddress.ip_network(target, strict=False).version == 6
    except ValueError:
        return False


def is_network_range(target: str) -> bool:
    """True for a CIDR block covering more than one address. Such runs need nmap to discover the live hosts."""
    try:
        return ipaddress.ip_network(target, strict=False).num_addresses > 1
    except ValueError:
        return False


def is_hostname(target: str) -> bool:
    """True when a validated target is a DNS name rather than an IP address or a network range.

    The web stages then probe URLs by that name, so a server that serves several sites by name (virtual
    hosting) answers for the right one instead of its default site.
    """
    return not _is_ip(target) and not is_network_range(target)
