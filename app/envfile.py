"""Read-modify-write access to the project's .env file, used by the dashboard's Settings page.

update_env_file() changes only the keys it is given and keeps comments, ordering and unrelated keys, so a
hand-edited .env survives a save from the dashboard. It reads the file with python-dotenv's own parser, so it
sees exactly the settings the server sees, and it refuses a save that would change any other setting.
Writes are serialised by a lock and atomic (temporary file, then rename), and the file's permission bits are
preserved so a private 0600 .env stays private on Linux/WSL. Values that need quoting are written in single
quotes. python-dotenv still treats a backslash there as an escape and expands ${NAME}, so validate_value()
refuses the few values that would not read back unchanged.
"""
from __future__ import annotations

import os
import re
import stat
import tempfile
import threading
import time
from contextlib import suppress
from io import StringIO
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from dotenv.parser import parse_stream

# "KEY=..." or "export KEY=...". Group 1 is the key.
_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
_EXPORT_RE = re.compile(r"\s*export[ \t]+")
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")  # a key name that cannot break or forge a KEY=value line
# Characters that would change the meaning of an unquoted value: whitespace, comments, quotes, $ and so on.
_NEEDS_QUOTES_RE = re.compile(r"[\s#\"'$`\\=]")
# Every character str.splitlines() treats as a line boundary, plus DEL: \x1c-\x1e, \x85, \u2028 and \u2029
# would otherwise turn one quoted value into several KEY=value lines when the file is read back.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")
# The line breaks python-dotenv recognises; the file is split on these and nothing else.
_LINE_BREAK_RE = re.compile(r"\r\n|\n|\r")
_BOM = "\ufeff"  # the byte-order mark some Windows editors put at the start of a UTF-8 file
_ADDED_KEYS_HEADER = "# ---- added from the dashboard settings page ----"
_write_lock = threading.Lock()


class EnvValueError(ValueError):
    """A value cannot be stored safely in .env. The message says why and is shown to the operator."""


def validate_value(value: str, label: str = "value") -> str:
    """Return `value` unchanged, or raise EnvValueError when it cannot be written safely.

    A line break would let one setting inject a second KEY=value line, and a single quote would end the
    single-quoted form that format_value() uses. Inside that form python-dotenv reads a backslash as an
    escape: a trailing one would hide the closing quote, so the value would run on over the following lines
    (the target allow-list among them) and they would be lost, and a doubled one would come back single.
    ${NAME} is expanded.
    """
    if _CONTROL_CHARS_RE.search(value):
        raise EnvValueError(f"{label} must not contain line breaks or control characters.")
    if "'" in value:
        raise EnvValueError(f"{label} must not contain single quotes.")
    if value.endswith("\\") or "\\\\" in value:
        raise EnvValueError(f"{label} must not end with a backslash or contain two backslashes in a row.")
    if "${" in value:  # python-dotenv expands ${NAME} even inside single quotes
        raise EnvValueError(f"{label} must not contain '${{'.")
    return value


def format_value(value: str) -> str:
    """Render a value for the right-hand side of KEY=: as-is when that is safe, otherwise in single quotes."""
    if value == "":
        return ""
    if _NEEDS_QUOTES_RE.search(value):
        return f"'{value}'"
    return value


def update_env_file(path: Path, updates: dict[str, str | None]) -> None:
    """Set each key in `updates` to its value; None or "" clears it (the line becomes KEY=).

    The first existing line for a key is rewritten in place and later duplicates are removed, because
    python-dotenv would otherwise use the last one. Keys that are not in the file yet are appended under a
    short comment. Every value is validated before anything is written, and the new content must read back
    with every other setting unchanged, so a bad value or an unreadable file changes nothing.
    """
    for key, value in updates.items():
        if not _KEY_RE.fullmatch(key):
            raise EnvValueError(f"{key!r} is not a valid .env key name.")
        validate_value(value or "", key)

    with _write_lock:
        # Read exactly as config.py reads it: python-dotenv strips one byte-order mark by itself, so the writer
        # and the server see the same keys (a second mark would be part of the first key for both).
        old = path.read_text(encoding="utf-8") if path.exists() else ""
        old = "\n".join(_LINE_BREAK_RE.split(old))  # python-dotenv reads \r\n, \r and \n alike; the file gets \n
        new = _apply_updates(old, updates)
        if old.startswith(_BOM) and new.startswith(_BOM):
            new = _BOM + new  # the parser dropped the first mark; a second one must stay part of the first key
        _check_round_trip(old, new, updates)
        _write_atomically(path, new)


def _apply_updates(text: str, updates: dict[str, str | None]) -> str:
    """Return the new file content: assignments rewritten, duplicates dropped, new keys appended.

    The file is split into bindings by python-dotenv's own parser, so a line inside another key's quoted value
    is never mistaken for an assignment, whatever it looks like. A line the parser cannot read (an unclosed
    quote) is ignored by python-dotenv; when it is an assignment of a key being saved, it is replaced like a
    valid one. When the old binding of a key being saved spans several lines (a quoted value over several
    lines, or text that python-dotenv swallowed along with a broken line), the lines after its first stay in
    the file as comments: they were not settings before and are not now, and nothing typed is lost. A
    rewritten line keeps its "export " prefix and the comment at its end.
    """
    remaining = dict(updates)
    output: list[str] = []
    for binding in parse_stream(StringIO(text)):
        lines = binding.original.string.split("\n")
        if lines[-1] == "":
            lines.pop()  # the binding's final newline ends its last line; it does not start an empty one
        blank = 0
        while blank < len(lines) and not lines[blank].strip():
            blank += 1  # the parser counts the blank lines before a binding as part of it
        output.extend(lines[:blank])
        lines = lines[blank:]
        key = binding.key
        if binding.error and lines:
            match = _ASSIGNMENT_RE.match(lines[0])
            key = match.group(1) if match else None
        if key not in updates:
            output.extend(lines)
            continue
        if key in remaining:  # the first binding of the key is rewritten in place; later duplicates are dropped
            export = "export " if lines and _EXPORT_RE.match(lines[0]) else ""
            comment = _inline_comment(lines[0], binding) if len(lines) == 1 and not binding.error else ""
            output.append(f"{export}{key}={format_value(remaining.pop(key) or '')}{comment}")
        output.extend(f"# {line}" if line.strip() else line for line in lines[1:])
    if remaining:
        if _ADDED_KEYS_HEADER not in output:  # one header is enough, however many saves append keys
            if output and output[-1].strip():
                output.append("")
            output.append(_ADDED_KEYS_HEADER)
        output.extend(f"{key}={format_value(value or '')}" for key, value in remaining.items())
    return "\n".join(output) + "\n"


def _inline_comment(line: str, binding: Any) -> str:
    """The comment at the end of a one-line binding (" # note"), or "". It starts at the first " #" before which
    python-dotenv still reads the same binding, so a # inside a quoted value is not taken for one."""
    for match in re.finditer(r"[ \t]+#", line):
        head = next(parse_stream(StringIO(line[:match.start()])), None)
        if head is not None and not head.error and (head.key, head.value) == (binding.key, binding.value):
            return line[match.start():]
    return ""


def _check_round_trip(old: str, new: str, updates: dict[str, str | None]) -> None:
    """Refuse a save whose new content would not read back as intended: each saved key with its new value, and
    every other setting exactly as before. The writer above is built for that; this check makes sure of it."""
    before = dotenv_values(stream=StringIO(old), interpolate=False)
    after = dotenv_values(stream=StringIO(new), interpolate=False)
    for key in (before.keys() | after.keys()) - updates.keys():
        if before.get(key) != after.get(key) or (key in before) != (key in after):
            raise EnvValueError(f"Saving would also change {key}, because the .env file has a line that cannot be "
                                "read safely. Nothing was written; correct the file by hand and save again.")
    for key, value in updates.items():
        if after.get(key) != (value or ""):
            raise EnvValueError(f"{key} would not read back as saved. Nothing was written; check the .env file.")


def _write_atomically(path: Path, text: str) -> None:
    """Replace the file at `path` with `text` without ever leaving a half-written file behind.

    The text goes to a temporary file in the same directory, which then replaces the original in a single
    os.replace() call. The original permission bits are copied over first.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = _permission_bits(path)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        if mode is not None:
            with suppress(OSError):
                os.chmod(temp_name, mode)
        _replace_with_retry(temp_name, path)
    except BaseException:
        # The original's permission bits were copied to the temporary file, so a read-only .env (which is also
        # why the replace failed on Windows) would leave a read-only copy of the new contents, API key
        # included, that os.remove() cannot delete: make it writable first.
        with suppress(OSError):
            os.chmod(temp_name, stat.S_IREAD | stat.S_IWRITE)
        with suppress(OSError):
            os.remove(temp_name)
        raise


# On Windows, replacing a file fails with PermissionError while another handle has it open. Settings are
# re-read from .env on every request (Settings.reload in config.py), so a save from the dashboard can collide
# with a concurrent request's read; that read finishes within milliseconds, so a short retry covers it.
_REPLACE_ATTEMPTS = 40
_REPLACE_DELAY_SECONDS = 0.025


def _replace_with_retry(source: str, path: Path) -> None:
    """os.replace() that waits out a transient Windows sharing violation instead of failing the save."""
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(source, path)
            return
        except PermissionError:
            if attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_DELAY_SECONDS)


def _permission_bits(path: Path) -> int | None:
    """The file's rwx permission bits, or None when it does not exist or cannot be inspected."""
    try:
        return os.stat(path).st_mode & 0o777
    except OSError:
        return None
