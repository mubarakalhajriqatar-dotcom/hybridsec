"""Safe subprocess execution for the scanners.

Commands are argument lists and never pass through a shell, so a target string cannot inject extra
commands. Every call has a hard timeout, stdin is closed so a tool that asks a question cannot hang the
run, and the output kept is capped. Live child processes are tracked so a server shutdown can kill
scans that would otherwise outlive it (see the lifespan handler in main.py, and install_exit_cleanup() for
an exit that skips it). Each scanner starts in its own process group and is killed with everything it
started, because a tool may be a wrapper (nikto.bat, a shell script) whose real scanner is a grandchild that
would otherwise keep running. On Windows the tree is found through the wrapper, so a wrapper that starts
the scanner in the background and exits at once leaves it behind, and the output read so far is lost when
the wait for its pipes gives up; the scanners run under WSL there anyway.

Custom tools (registered on the dashboard's Custom tools page, see tools/custom.py) are read with a hard character
limit instead (run_command's max_chars): a tool that keeps printing is stopped as soon as its standard output or its
standard error passes the limit, so neither the tool nor a target that streams forever can fill the server's memory.
The two streams are counted separately, so a tool that writes a lot of progress text on standard error does not lose
its result on standard output.
"""
from __future__ import annotations

import atexit
import codecs
import contextlib
import io
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

# stdout and stderr are each truncated to this many characters before they are stored or parsed.
MAX_OUTPUT_CHARS = 2_000_000

_live: set[subprocess.Popen] = set()
_live_lock = threading.Lock()
_shutting_down = False  # set by terminate_all(): once shutdown has begun, no new scanner may start
_interrupted: set[subprocess.Popen] = set()  # processes terminate_all() killed, so run_command() can say so
_cleanup_installed = False  # set by install_exit_cleanup()
# After a kill, how long to wait for the pipes to close before giving up on the rest of the output. Public,
# because the custom-tool stage leaves this much room before the run deadline (hybrid.py).
DRAIN_SECONDS = 5.0


@dataclass
class CommandResult:
    """What one tool invocation produced.

    exit_code is the program's own exit code, or None when run_command stopped it: killed at the timeout, or killed
    for printing more than max_chars. interrupted is True when terminate_all() killed it because the server shut
    down while it ran (exit_code is then whatever the kill left). truncated is True when stdout or stderr passed
    max_chars: the output read from that stream stops there, and the process is stopped for it unless it had
    already exited (exit_code then tells the two apart). started is False when the process could not be started at
    all (set by the pipeline, see hybrid._start_tool; run_command raises instead)."""

    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    interrupted: bool = False
    truncated: bool = False
    started: bool = True


def run_command(command: list[str], timeout: float, max_chars: int | None = None) -> CommandResult:
    """Run `command` and wait at most `timeout` seconds (minimum one second).

    A non-zero exit does not raise: callers inspect exit_code and the output, because scanners often exit
    non-zero after printing useful results. On timeout the process is killed and whatever it had already
    written is still returned, which lets the pipeline salvage partial Nmap XML.

    With `max_chars`, at most that many characters of stdout and at most that many of stderr are read, and a process
    that prints more on either of them is stopped at once, with exit_code None (used for custom tools). Without it,
    the output is read whole and then cut to MAX_OUTPUT_CHARS, as the built-in scanners need.
    """
    # A bare string would be iterated character by character, so the type is checked explicitly.
    if not isinstance(command, (list, tuple)) or not command or not all(isinstance(part, str) for part in command):
        raise ValueError("Command must be a non-empty list of strings.")
    started = time.monotonic()
    with _live_lock:
        # Check, start and register in one step, so terminate_all() either kills this process or stops it
        # from starting: a worker thread must not launch the next scanner after shutdown has begun.
        if _shutting_down:
            raise OSError("the server is shutting down")
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
            shell=False,
            **_own_process_group(),
        )
        _live.add(proc)
    timed_out = truncated = stopped = False
    try:
        if max_chars is not None:
            stdout, stderr, timed_out, truncated, stopped = _read_capped(proc, timeout, max_chars)
        else:
            try:
                stdout, stderr = proc.communicate(timeout=max(1.0, timeout))
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=DRAIN_SECONDS)  # what was written before the kill
                except subprocess.TimeoutExpired as late:
                    # Something the kill did not reach still holds the pipes: the time limit wins over the output.
                    stdout, stderr = _as_text(late.output), _as_text(late.stderr)
    finally:
        with _live_lock:
            _live.discard(proc)
            interrupted = proc in _interrupted
            _interrupted.discard(proc)
    return CommandResult(
        command=command,
        exit_code=None if timed_out or stopped else proc.returncode,  # a kill's status is not the program's
        stdout=(stdout or "")[:MAX_OUTPUT_CHARS],
        stderr=(stderr or "")[:MAX_OUTPUT_CHARS],
        duration_seconds=round(time.monotonic() - started, 3),
        timed_out=timed_out,
        interrupted=interrupted,
        truncated=truncated,
    )


def _read_capped(proc: subprocess.Popen, timeout: float, limit: int) -> tuple[str, str, bool, bool, bool]:
    """Read stdout and stderr on two threads, keeping at most `limit` characters of each, and stop the process as
    soon as either of them passes the limit. Returns (stdout, stderr, timed_out, truncated, stopped): truncated says
    a stream passed the limit, stopped that the process was still running and was killed for it.

    Each stream has its own count, so a tool that writes a lot to standard error (only part of which is kept, see
    tools/custom.py) still runs to the end and keeps its standard output."""
    kept: dict[str, list[str]] = {"stdout": [], "stderr": []}
    kept_lock = threading.Lock()  # a reader may still append after a timeout while the output is joined
    state = {"stopped": False}  # whether the flood kill stopped a process that was still running
    flooded = threading.Event()
    timing_out = threading.Event()  # set before the kill at the time limit: output drained after it is no flood

    def read(name: str, pipe) -> None:
        # Whatever the pipe holds is read at once (at most 64 KiB), so a tool that prints a long text without a line
        # break and then waits is still stopped at the limit. Decoded as the text-mode pipe would (newlines too).
        decoder = io.IncrementalNewlineDecoder(
            codecs.getincrementaldecoder(pipe.encoding)(errors=pipe.errors or "replace"), translate=True)
        size = 0  # characters read from this pipe
        while True:
            data = pipe.buffer.read1(65536)
            chunk = decoder.decode(data, final=not data)
            with kept_lock:
                if chunk and size < limit:
                    kept[name].append(chunk[:limit - size])
                size += len(chunk)
                over = size > limit and not flooded.is_set()
                if over:
                    flooded.set()
            if over and not timing_out.is_set():
                state["stopped"] = proc.poll() is None  # a program that already exited keeps its own exit code
                _kill(proc)
            if not data:
                break

    readers = [threading.Thread(target=read, args=(name, getattr(proc, name)), daemon=True) for name in kept]
    try:
        for reader in readers:
            reader.start()
    except BaseException:
        _kill(proc)  # the process is already running: do not leave it behind, untracked and unread
        raise
    end = time.monotonic() + max(1.0, timeout)
    # The call is over when both pipes are closed, as with communicate(), not when the direct child exits: a helper
    # the tool started may still hold them, and it must be stopped at the time limit too.
    for reader in readers:
        reader.join(max(0.0, end - time.monotonic()))
    timed_out = any(reader.is_alive() for reader in readers)
    if not timed_out:
        try:
            proc.wait(timeout=max(0.0, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    if timed_out:
        timing_out.set()
        _kill(proc)  # POSIX: killpg also reaches a helper left in the group after its leader exited
        drain_end = time.monotonic() + DRAIN_SECONDS  # one drain for both pipes: the margin _run_custom reserves
        for reader in readers:
            reader.join(max(0.0, drain_end - time.monotonic()))
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=max(0.0, drain_end - time.monotonic()))  # reap the killed process
    with kept_lock:
        stdout, stderr = "".join(kept["stdout"]), "".join(kept["stderr"])  # a reader may still run after a timeout
    return stdout, stderr, timed_out, flooded.is_set(), state["stopped"]


def terminate_all() -> int:
    """Kill every scanner process that is still running and refuse to start new ones (called on server
    shutdown). Returns how many were killed. accept_new_processes() re-arms run_command() at startup."""
    global _shutting_down
    with _live_lock:
        _shutting_down = True
        procs = list(_live)
        _interrupted.update(procs)  # recorded before the kill, so each run_command() call reports it on return
    for proc in procs:
        _kill(proc)
    return len(procs)


def install_exit_cleanup() -> None:
    """Make sure no scanner outlives the server when the lifespan shutdown does not run: uvicorn skips it on a
    forced exit (a second Ctrl+C), and a closed terminal (SIGHUP) ends the process without it. A scanner runs in
    a process group of its own, so the terminal's signals do not reach it directly. Called at startup; the
    hangup handler can only be set from the main thread (an in-process test client starts elsewhere)."""
    global _cleanup_installed
    if _cleanup_installed:
        return
    _cleanup_installed = True
    atexit.register(terminate_all)
    hangup = getattr(signal, "SIGHUP", None)  # POSIX only
    if hangup is not None:
        with contextlib.suppress(ValueError, OSError):
            if signal.getsignal(hangup) == signal.SIG_DFL:
                signal.signal(hangup, _on_hangup)


def _on_hangup(signum: int, frame: object) -> None:
    """Kill the scanners, then end the process the way a hangup always did."""
    terminate_all()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def is_shutting_down() -> bool:
    """True between terminate_all() and the next accept_new_processes(). A run that is still executing then
    ends as interrupted instead of starting its next stage (see RunManager._execute in hybrid.py)."""
    return _shutting_down


def accept_new_processes() -> None:
    """Allow run_command() again after an earlier terminate_all() in this process. Called at startup, because
    one process can host several application lifespans: the test suite does, and so does an in-process restart."""
    global _shutting_down
    with _live_lock:
        _shutting_down = False


def _own_process_group() -> dict:
    """Popen options that start the scanner in a process group of its own, so _kill() can stop the whole tree."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _kill(proc: subprocess.Popen) -> None:
    """Kill a process and every process it started, ignoring the errors raised when they have already exited.

    A wrapper (nikto.bat run by cmd.exe, a shell script) leaves the real scanner as a grandchild that keeps the
    output pipes open, so killing only the direct child would let the scan run on past its time limit.
    """
    if os.name != "nt":
        # The scanner leads its own group (start_new_session). The group is killed even when its leader has
        # already exited: a wrapper may have left the real scanner running in the background.
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
    elif proc.poll() is None:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], check=False, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=10,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    with contextlib.suppress(OSError):
        proc.kill()  # the direct child, in case the tree kill could not run


def _as_text(value: object) -> str:
    """Output attached to a TimeoutExpired, which may be bytes, text or missing."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else ""
