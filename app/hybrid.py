"""The hybrid pipeline: runs the selected tools in stage order and feeds each stage's results to the next.

Stages (one per tool):
  port_scan        Nmap     target -> open ports, and which of them are web services
  web_fingerprint  WhatWeb  web services -> technologies and versions per URL
  web_vuln_scan    Nikto    web services that answered -> findings
  custom_tool      operator-registered tools (tools/custom.py)  target or web URLs -> raw output kept, not parsed
                   or scored; they run last, after at least one built-in tool

RunManager.create() registers a run and executes it on a background thread, so the HTTP request returns at
once (202 Accepted) and the dashboard polls for progress. While a run executes, its in-memory copy is the
live view; every stage transition is also saved to SQLite, so a restart never loses completed work. The
time budget gives each stage a slot, one after the other. A web stage starts no URL after its slot ends (or,
when an earlier stage overran, after its whole share), so its slow URLs cannot use up a later stage's time;
one run-wide deadline bounds the whole pipeline. URLs that no longer fit are skipped.
A stage that did not examine everything it was given (it ran out of time, or a tool produced nothing for a
URL) is marked partial; a run that completes with such a stage, or with a failed later stage, carries the flag
in its summary, so that the history, the reports and the comparison never present an incomplete scan as a
complete one.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
import os
import socket
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from typing import TypedDict

from . import storage
from .config import settings
from .schemas import (
    CustomTool,
    CustomToolOutput,
    ExecuteRequest,
    PortFinding,
    Run,
    RunSummary,
    StageResult,
    VulnFinding,
    WebFinding,
)
from .security import is_hostname, is_ipv6_target
from .tools import parsers
from .tools.custom import (
    CUSTOM_STAGE,
    RUN_OUTPUT_CHARS,
    STDERR_CHARS,
    STDOUT_CHARS,
    build_command,
    clean_output,
    find_program,
)
from .tools.registry import TOOLS, ToolProfile, profile_for_run, resolve_binary
from .tools.runner import DRAIN_SECONDS, MAX_OUTPUT_CHARS, CommandResult, is_shutting_down, run_command

log = logging.getLogger("hybridsec.pipeline")

# The web stages probe at most this many services per run, so one large host cannot keep them busy for hours.
MAX_WEB_TARGETS = 12
# A URL is only started when at least this much time is left; a shorter probe would just time out.
MIN_WHATWEB_SECONDS = 10.0
MIN_NIKTO_SECONDS = 20.0
# Share of the run's time budget that each tool's stage receives (rescaled over the tools in the run).
STAGE_TIME_WEIGHTS = {"nmap": 0.55, "whatweb": 0.2, "nikto": 0.25}
# All the custom tools of a run share this one weight, so however many are ticked they take a bounded share (weight
# 0.2) from the built-in stages' shares, but never the minimum times those stages need (see _stage_budgets). A custom
# call is only started when at least MIN_CUSTOM_SECONDS are left for it; a budget that cannot leave that much after
# the built-in stages' minimums gives the custom stages no share, so a call runs only on time the built-in stages
# leave over (see _stage_budgets and _custom_budget_needed).
CUSTOM_TOOLS_WEIGHT = 0.2
MIN_CUSTOM_SECONDS = 10.0
# The least time a stage needs to probe one target; shares below this are lifted when the budget allows.
STAGE_MIN_SECONDS = {"nmap": 10.0, "whatweb": MIN_WHATWEB_SECONDS, "nikto": MIN_NIKTO_SECONDS}
# Seconds allowed for the moment between two clock readings when the time left is rounded (_time_for_next_url).
CLOCK_SLACK = 0.05


class RunLimitExceeded(RuntimeError):
    """Raised by RunManager.create() when HYBRIDSEC_MAX_CONCURRENT_RUNS runs are already executing."""


class RunInterrupted(RuntimeError):
    """Raised on the worker thread when the server shuts down while a run executes: its scanner was killed
    (see _start_tool) or the next one may not start, so the run is recorded as failed for that reason."""


# Recorded on a run, and on its stages that never ran, when the server shut down while it executed.
SHUTDOWN_REASON = "The server shut down before this run finished."


class StageContext(TypedDict, total=False):
    """What the stages of one run hand to each other. At runtime it is a plain dict with these keys.

    deadline   time.monotonic() value at which the whole run must stop (set by RunManager)
    slot_end   time.monotonic() value at which the current stage's slot ends: the run's start plus the shares
               of this stage and every earlier one (set by RunManager, used by _stage_end)
    hosts_up   written by the port scan, used by summarize()
    web_ports  written by the port scan: the web services both web stages probe
    web_dropped  written by the port scan: how many web services it found beyond MAX_WEB_TARGETS (not probed)
    web        written by the fingerprint stage: the vulnerability scan only probes URLs that answered it
    fingerprinted  set when the fingerprint stage ran, even if it recorded no URL (none could be probed)
    interrupted  set by _start_tool when the server's shutdown killed a tool: the run then ends as failed
    budget     the run's time budget in seconds (set by RunManager): a custom stage that cannot start names the
               budget that would be enough
    """

    deadline: float
    slot_end: float
    hosts_up: int
    web_ports: list[PortFinding]
    web_dropped: int
    web: list[WebFinding]
    fingerprinted: bool
    interrupted: bool
    budget: int


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Run lifecycle --------------------------------------------------------------------------------

class RunManager:
    """Starts runs on worker threads and keeps track of the ones still executing.

    `_active` maps a run id to the live Run object that a worker thread is filling in. The lock guards that
    dict and every change a reader must not see half-done; readers only ever get deep copies.
    """

    def __init__(self) -> None:
        self._active: dict[str, Run] = {}
        self._lock = threading.Lock()

    # --- Public API -------------------------------------------------------------------------------

    def create(self, request: ExecuteRequest, target: str, tools: list[str], plan_id: str | None,
               timeout_seconds: int, profiles: dict[str, str] | None = None,
               custom_tools: dict[str, CustomTool] | None = None) -> Run:
        """Register a queued run, save it, and start executing it on a background thread.

        `profiles` maps each tool to the profile key it should use (the router validated them); a tool
        without one uses its default. `custom_tools` holds the definition of each custom tool in `tools`; the
        run keeps its own copy, so deleting or re-registering the tool later does not change it. Raises
        RunLimitExceeded when the concurrent-run cap is reached. The queued run is returned at once; callers
        poll get() to follow its progress.
        """
        custom_tools = custom_tools or {}
        run = Run(
            id=uuid.uuid4().hex[:12],
            # A blank label would be shown as an empty run title in the history, so it counts as "no label".
            label=(request.label or "").strip() or None,
            target=target,
            status="queued",
            mode="simulated" if request.simulate else "live",
            plan_id=plan_id,
            tools=tools,
            profiles={t: profile_for_run(t, profiles).key for t in tools if t in TOOLS},
            custom_tools={t: custom_tools[t] for t in tools if t in custom_tools},
            created_at=_now(),
            stages=[StageResult(stage=CUSTOM_STAGE if t in custom_tools else TOOLS[t].stage, tool=t) for t in tools],
        )
        chosen = ", ".join(f"{tool}={key}" for tool, key in run.profiles.items())
        run.log.append(f"[{run.created_at.isoformat(timespec='seconds')}] run {run.id} queued for {target} "
                       f"using {', '.join(tools)} ({run.mode} mode, {timeout_seconds}s budget, profiles {chosen})")
        with self._lock:
            # Check and reserve the slot in one step, so parallel requests cannot all slip past the cap.
            if len(self._active) >= settings.max_concurrent_runs:
                # The count is the runs really executing: after the operator lowers the cap it can be higher.
                raise RunLimitExceeded(
                    f"{len(self._active)} run(s) are already executing (the limit is "
                    f"{settings.max_concurrent_runs}). Wait for one to finish before starting another."
                )
            self._active[run.id] = run
        try:
            storage.save_run(run)
        except Exception:
            with self._lock:
                self._active.pop(run.id, None)  # give the slot back: the run never started
            raise
        thread = threading.Thread(target=self._execute, args=(run, request, timeout_seconds), daemon=True,
                                  name=f"run-{run.id}")
        # The caller gets the queued run as a copy taken before the worker starts: the 202 body is then a
        # consistent snapshot, not the object the worker thread mutates while FastAPI serialises it.
        queued = run.model_copy(deep=True)
        try:
            thread.start()
        except Exception as exc:  # RuntimeError "can't start new thread": the run never begins
            self._abandon(run, f"The server could not start this run: {exc}")
            raise
        return queued

    def _abandon(self, run: Run, reason: str) -> None:
        """Record a run whose worker thread could not start as failed, and give its concurrency slot back:
        otherwise it would stay "queued", count against the cap and refuse deletion until the next restart."""
        with self._lock:
            self._active.pop(run.id, None)
            run.status = "failed"
            run.error = reason
            run.finished_at = _now()
            for stage in run.stages:
                stage.status = "skipped"
                stage.error = reason
            run.log.append(f"[{run.finished_at.isoformat(timespec='seconds')}] {reason}")
        try:
            storage.save_run(run)
        except Exception:  # the exception the caller re-raises already says what went wrong
            log.exception("%s could not save the run that failed to start", run.id)

    def get(self, run_id: str) -> Run | None:
        """A snapshot of a run: the live copy while it executes, otherwise the saved one (None if unknown)."""
        with self._lock:
            live = self._active.get(run_id)
            if live is not None:
                return live.model_copy(deep=True)
        return storage.get_run(run_id)

    def is_active(self, run_id: str) -> bool:
        """True while the run is queued or executing. Such a run must not be deleted."""
        with self._lock:
            return run_id in self._active

    def wait_until_idle(self, timeout: float) -> bool:
        """Wait up to `timeout` seconds for every executing run to finish; True when none is left. Used at
        shutdown after the scanners were killed: the worker threads are daemons, so without the wait the
        process could exit before a run records that the shutdown interrupted it."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if not self._active:
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def add_log(self, run: Run, message: str) -> None:
        """Append a timestamped line to the run's log (shown live on the dashboard) and to the server log."""
        line = f"[{_now().isoformat(timespec='seconds')}] {message}"
        with self._lock:
            run.log.append(line)
        log.info("%s %s", run.id, message)

    def add_output(self, run: Run, output: CustomToolOutput) -> None:
        """Append what a custom tool call printed to the run (shown live on the Tool output tab)."""
        with self._lock:
            run.custom_outputs.append(output)

    # --- Execution (on the worker thread) ---------------------------------------------------------

    def _execute(self, run: Run, request: ExecuteRequest, timeout_seconds: int) -> None:
        """Run every stage in order, then publish the summary and the final status.

        A crashing stage is recorded and the next stage still runs. Whatever happens, _finish() publishes a
        final state and frees the concurrency slot.
        """
        started = _now()
        with self._lock:
            run.status = "running"
            run.started_at = started
        budgets = _stage_budgets(run.tools, timeout_seconds)
        clock = time.monotonic()
        # One deadline for the whole run: its time budget plus a 5-second margin.
        context: StageContext = {"web_ports": [], "web": [], "deadline": clock + timeout_seconds + 5,
                                 "budget": timeout_seconds}
        slot_end = clock  # the stages' slots follow each other in stage order, each as long as its share
        final_status = "failed"
        final_error: str | None = None
        try:
            self._persist(run)
            for stage in run.stages:
                slot_end += budgets[stage.tool]
                context["slot_end"] = slot_end
                self._run_stage(run, request, stage, context, budgets[stage.tool])
                if context.get("interrupted"):  # the shutdown killed the stage's tool or kept it from starting
                    raise RunInterrupted(SHUTDOWN_REASON)
            summary = summarize(run, context.get("hosts_up"))
            final_status, final_error = _final_outcome(run.stages)
            with self._lock:
                run.summary = summary
        except RunInterrupted as exc:
            # Recorded for what it is: a shutdown, not a tool failure. The stages that never ran are skipped;
            # a restart would otherwise find the run "running" and fail it with the restart reason instead.
            final_status, final_error = "failed", str(exc)
            with self._lock:
                for stage in run.stages:
                    if stage.status in {"pending", "running"}:
                        stage.status = "skipped"
                        stage.error = str(exc)
            self.add_log(run, str(exc))
            self._summarize_failed(run, context)
        except Exception as exc:
            # A crash outside the stage handlers (a failed save, for example). Recorded like an interrupted
            # run: the stages that never finished are closed with the error instead of staying "pending".
            final_status, final_error = "failed", f"{type(exc).__name__}: {exc}"
            log.exception("%s pipeline error", run.id)
            with self._lock:
                for stage in run.stages:
                    if stage.status in {"pending", "running"}:
                        stage.status = "failed"
                        stage.error = final_error
            self.add_log(run, f"pipeline error: {final_error}")
            self._summarize_failed(run, context)
        finally:
            self._finish(run, started, final_status, final_error)

    def _summarize_failed(self, run: Run, context: StageContext) -> None:
        """The summary of a run that failed after some stages finished: those stages keep their ports,
        services and findings, so it counts them like any other failed run's summary does, or the KPIs and
        reports would show zeros. A summary that cannot be computed leaves the empty one."""
        try:
            summary = summarize(run, context.get("hosts_up"), failed=True)
        except Exception:
            log.exception("%s could not summarise the failed run", run.id)
        else:
            with self._lock:
                run.summary = summary

    def _run_stage(self, run: Run, request: ExecuteRequest, stage: StageResult, context: StageContext,
                   stage_timeout: float) -> None:
        """Run one stage handler and record its timing. A crash fails this stage only, not the run."""
        handler = STAGE_HANDLERS[stage.stage]
        with self._lock:
            stage.status = "running"
            stage.started_at = _now()
        self._persist(run)
        try:
            handler(self, run, request, stage, context, stage_timeout)
        except Exception as exc:
            with self._lock:
                stage.status = "failed"
                stage.error = f"{type(exc).__name__}: {exc}"
            self.add_log(run, f"{stage.tool} crashed: {stage.error}")
        with self._lock:
            stage.finished_at = _now()
            stage.duration_seconds = round((stage.finished_at - stage.started_at).total_seconds(), 3)
        self._persist(run)

    def _finish(self, run: Run, started: datetime, status: str, error: str | None) -> None:
        """Publish the final state, save it, and free the run's slot, even when saving fails."""
        finished = _now()
        with self._lock:
            # All final fields change in one locked step, so a concurrent poll never sees a half-finished run.
            run.status = status
            run.error = error
            run.finished_at = finished
            run.duration_seconds = round((finished - started).total_seconds(), 3)
            run.log.append(f"[{finished.isoformat(timespec='seconds')}] run {run.status} in {run.duration_seconds}s")
        try:
            self._persist(run)
        except Exception:
            log.exception("%s could not persist final state", run.id)
        finally:
            with self._lock:
                self._active.pop(run.id, None)

    def _persist(self, run: Run) -> None:
        """Save a consistent snapshot of the run: copied under the lock, written to SQLite outside it."""
        with self._lock:
            snapshot = run.model_copy(deep=True)
        storage.save_run(snapshot)


def _final_outcome(stages: list[StageResult]) -> tuple[str, str | None]:
    """The run's final (status, error), decided from its stages.

    Only the first stage is essential: when it failed, the later stages had no real input, so the run
    failed. When a later stage failed, the earlier results are still useful, so the run is "completed"
    and its error lists the stages that failed.
    """
    if stages and stages[0].status == "failed":
        return "failed", stages[0].error
    failed = [s for s in stages if s.status == "failed"]
    return "completed", "; ".join(f"{s.tool}: {s.error}" for s in failed) or None


# --- Stage helpers --------------------------------------------------------------------------------

# How a WhatWeb stage that reached no web service at all begins its error. _highlights() relies on it to
# tell "nothing answered" (a result) from "nothing could be probed" (no result).
WHATWEB_NO_RESPONSE = "WhatWeb got no response from any web service"


def join_notes(notes: list[str]) -> str | None:
    """A stage's notes as one text, each ending with a full stop so that two notes never run together;
    None when there is nothing to say."""
    return " ".join(note if note.endswith((".", "!", "?")) else note + "." for note in notes) or None


def _stop_stage(manager: RunManager, run: Run, stage: StageResult, status: str, reason: str,
                log_message: str | None = None) -> None:
    """End a stage as failed or skipped: the reason is stored on the stage and written to the run log."""
    stage.status = status
    stage.error = reason
    manager.add_log(run, log_message or reason)


def _require_binary(manager: RunManager, run: Run, stage: StageResult) -> str | None:
    """Path of the stage's tool, or None after marking the stage failed because the tool is not installed."""
    spec = TOOLS[stage.tool]
    path = resolve_binary(spec)
    if path is None:
        _stop_stage(manager, run, stage, "failed", f"{spec.display_name} is not installed. {spec.install_hint}")
    return path


# Exit code recorded when a scanner could not be started at all: the server is shutting down (run_command()
# then refuses new processes), or the binary vanished or lost its execute permission after resolve_binary()
# found it. 127 is the shell's "command not found" convention.
START_FAILED_EXIT_CODE = 127


def _start_tool(command: list[str], timeout: float, context: StageContext | None = None,
                max_chars: int | None = None) -> CommandResult:
    """run_command() that reports a failure to start the process as a result instead of raising.

    `max_chars` is passed on for custom tools: their output is read with that hard limit (see run_command).

    The OSError becomes a CommandResult with START_FAILED_EXIT_CODE, started False and the reason in stderr, so
    each stage treats it like any other failed probe: a readable message, and a web stage keeps the findings of
    the URLs it already probed. A scanner that the server's shutdown killed while it ran is reported the same
    way (whatever it printed is not a complete examination). A custom tool keeps what it printed before the
    shutdown, with interrupted set, because its text is its only result. In both shutdown cases `context` is
    marked interrupted, so that RunManager._execute() ends the run as interrupted instead of completing it.
    """
    try:
        if max_chars is None:
            result = run_command(command, timeout=timeout)
        else:
            result = run_command(command, timeout=timeout, max_chars=max_chars)
    except OSError as exc:
        if context is not None and is_shutting_down():  # run_command() refused: the server is shutting down
            context["interrupted"] = True
        reason = f"Could not start {os.path.basename(command[0])}: {exc}"
        return CommandResult(command=command, exit_code=START_FAILED_EXIT_CODE, stdout="", stderr=reason,
                             duration_seconds=0.0, started=False)
    if result.interrupted:
        if context is not None:
            context["interrupted"] = True
        if max_chars is not None:
            return result  # a custom tool: its output so far is kept, and _run_custom says the shutdown stopped it
        reason = f"{os.path.basename(command[0])} was stopped: the server is shutting down"
        return CommandResult(command=command, exit_code=START_FAILED_EXIT_CODE, stdout="", stderr=reason,
                             duration_seconds=result.duration_seconds, interrupted=True)
    return result


def _remaining(context: StageContext) -> float:
    """Seconds left before the run's deadline (an hour when there is none, e.g. a handler called directly)."""
    return context.get("deadline", time.monotonic() + 3600) - time.monotonic()


def _stage_end(context: StageContext, stage_timeout: float) -> float:
    """The time.monotonic() value after which a web stage starts no further URL.

    That is the end of the stage's slot (context["slot_end"]): the stage may use time that an earlier stage
    did not need, and its own slow URLs cannot run on into a later stage's share. A stage that starts after
    its slot has begun, because an earlier stage overran by a few seconds, still gets its whole share, so it
    may end those few seconds after its slot. Without slots (a stage handler called on its own) the stage
    gets its share from now.
    """
    return max(time.monotonic() + stage_timeout, context.get("slot_end", 0.0))


def _time_for_next_url(context: StageContext, stage_end: float, stage_timeout: float, url_count: int,
                       minimum: float) -> float | None:
    """How many seconds the next URL may take, or None when too little time is left to start it.

    Each URL gets an equal share of the stage budget, but never more than what is left before the stage
    ends (see _stage_end) or before the run's deadline, and never less than `minimum`. The time left is
    rounded down to whole seconds after adding CLOCK_SLACK: read from the clock, a whole 30 s share arrives as
    29.99999 s and would be passed to Nikto as -maxtime 29s, while a real shortfall is never rounded up.
    """
    remaining = math.floor(min(_remaining(context), stage_end - time.monotonic()) + CLOCK_SLACK)
    if remaining < minimum:
        return None
    return max(minimum, min(remaining, stage_timeout / url_count))


def _probe_host(run: Run) -> str | None:
    """The name to put in probe URLs: the operator's hostname when the target is one, else None (use the
    scanned address). A simulated run never needs it because its findings already carry the target."""
    return run.target if run.mode == "live" and is_hostname(run.target) else None


def _web_targets(run: Run, context: StageContext) -> list[PortFinding]:
    """The web services the web stages should probe.

    They normally come from the port scan. A workflow without a port scan has no way to discover them, so
    the target's standard web ports 80 and 443 are assumed.
    """
    web_ports: list[PortFinding] = context.get("web_ports") or []
    if not web_ports and "port_scan" not in [s.stage for s in run.stages]:
        return [PortFinding(host=run.target, port=80, service="http", is_web=True),
                PortFinding(host=run.target, port=443, service="https", is_web=True)]
    return web_ports


def _temp_path(prefix: str) -> str:
    """A new temporary .json file for a tool to write its report into."""
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".json")
    os.close(fd)
    return path


def _read_and_remove(path: str) -> str:
    """The contents of a tool's report file, capped like stdout ("" when unreadable); the file is deleted either way."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(MAX_OUTPUT_CHARS)
    except OSError:
        return ""
    finally:
        with suppress(OSError):
            os.remove(path)


# --- Stage 1: port scan (Nmap) --------------------------------------------------------------------

def stage_port_scan(manager: RunManager, run: Run, request: ExecuteRequest, stage: StageResult,
                    context: StageContext, timeout: float) -> None:
    """Find open ports and services, and pick out the web services for the later stages.

    Writes run.ports, context["hosts_up"] and context["web_ports"] (at most MAX_WEB_TARGETS of them).
    """
    top_ports = min(request.top_ports, settings.max_top_ports)
    profile = profile_for_run("nmap", run.profiles)
    if run.mode == "simulated":
        ports, hosts_up = simulate_ports(run.target, profile.key)
        # The command a live run would build (_run_nmap). Only an IPv6 address or block gets -6 here: a simulated run
        # never asks the resolver whether a hostname has only IPv6 records.
        ipv6 = " -6" if is_ipv6_target(run.target) else ""
        stage.command = (f"nmap {profile.flags} --open --top-ports {top_ports} --host-timeout "
                         f"{max(5, int(timeout * 0.8))}s{ipv6} -oX - {run.target}  (simulated)")
        stage.status = "simulated"
        manager.add_log(run, f"SIMULATED nmap: {len(ports)} open ports on {hosts_up} host(s)")
    else:
        scan = _run_nmap(manager, run, stage, top_ports, timeout, profile, context)
        if scan is None:
            return  # the stage failed, so there is nothing to hand on
        ports, hosts_up = scan.ports, scan.hosts_up

    run.ports = ports
    context["hosts_up"] = hosts_up
    web = [p for p in ports if p.is_web]
    context["web_ports"] = web[:MAX_WEB_TARGETS]
    context["web_dropped"] = max(0, len(web) - MAX_WEB_TARGETS)
    if len(web) > MAX_WEB_TARGETS:
        manager.add_log(run, f"limiting web stages to the first {MAX_WEB_TARGETS} of {len(web)} web services")


def _run_nmap(manager: RunManager, run: Run, stage: StageResult, top_ports: int,
              timeout: float, profile: ToolProfile | None = None,
              context: StageContext | None = None) -> parsers.NmapResult | None:
    """Run the real Nmap scan and judge its output. Returns None after marking the stage failed.

    `profile` supplies the scan options (-sV -Pn -T4 by default, see the registry); the port count, the
    time limits, the output format and the target are always added here.
    """
    binary = _require_binary(manager, run, stage)
    if binary is None:
        return None
    profile = profile or profile_for_run("nmap", run.profiles)
    # Nmap's per-host limit sits below the stage budget, so a slow host is reported as timed out by Nmap
    # itself; the subprocess timeout (which still salvages partial XML) is only the backstop.
    host_timeout = max(5, int(timeout * 0.8))
    command = [binary, *profile.args, "--open", "--top-ports", str(top_ports),
               "--host-timeout", f"{host_timeout}s"]
    if _scan_over_ipv6(run.target):
        command.append("-6")
        if not is_ipv6_target(run.target):
            manager.add_log(run, f"nmap: {run.target} resolves to IPv6 addresses only, scanning with -6")
    command += ["-oX", "-", run.target]
    stage.command = " ".join(command)
    manager.add_log(run, f"nmap: {stage.command}")

    result = _start_tool(command, timeout=timeout + 5, context=context)
    stage.exit_code = result.exit_code
    stage.raw_output_chars = len(result.stdout)
    scan = parsers.parse_nmap_xml_full(result.stdout)

    # No open ports can be a valid answer for a quiet host; it is only a failure when Nmap says why.
    if result.exit_code not in (0, None) and not scan.ports:
        error = (result.stderr.strip() or f"nmap exited with code {result.exit_code}")[:500]
        _stop_stage(manager, run, stage, "failed", error, log_message=f"nmap failed: {error}")
        return None
    combined_output = f"{result.stdout}\n{result.stderr}"
    if not scan.ports and ("Failed to resolve" in combined_output or "0 hosts scanned" in combined_output):
        _stop_stage(manager, run, stage, "failed",
                    f"nmap could not resolve or reach '{run.target}' (0 hosts scanned).")
        return None
    if scan.timed_out_hosts and not scan.ports:
        _stop_stage(manager, run, stage, "failed",
                    f"nmap gave up on {_host_list(scan.timed_out_hosts)} after {host_timeout}s (host timeout) "
                    "without finding an open port. Increase the time budget or reduce top_ports; the host may "
                    "be slow or heavily filtered.")
        return None
    if (result.timed_out or scan.truncated) and not scan.ports and scan.hosts_up == 0:
        # Nmap was stopped (or its XML cut off) before it finished a single host, so there is no evidence
        # either way; "completed, no open ports" here would be a false negative dressed up as a result.
        reason = (f"nmap hit the {round(timeout)}s stage time limit before it reported any host. "
                  "Increase the time budget or reduce top_ports; a network range needs more time than one host."
                  if result.timed_out else
                  "nmap output was cut off before it reported any host, so the scan produced no usable result.")
        _stop_stage(manager, run, stage, "failed", reason)
        return None

    # Stopped at the time limit, cut off, or hosts given up on: the port list is known to be incomplete.
    stage.partial = result.timed_out or scan.truncated or bool(scan.timed_out_hosts)
    stage.error = " ".join(_nmap_caveats(result, scan, timeout, host_timeout)) or None
    if stage.error:
        manager.add_log(run, stage.error)
    stage.status = "completed"
    manager.add_log(run, f"nmap: {scan.hosts_up} host(s) up, {len(scan.ports)} open port(s)"
                         + (" (partial)" if stage.partial else ""))
    return scan


def _nmap_caveats(result: CommandResult, scan: parsers.NmapResult, timeout: float, host_timeout: int) -> list[str]:
    """Why a completed Nmap scan may be incomplete. These become notes on the stage.

    The first three mean the results are partial. The last one is a complete answer (nothing open): with
    --open, a host without open ports is left out of the report, so a dead or fully filtered target shows
    up as no hosts at all.
    """
    caveats = []
    reported = f"{scan.hosts_up} host(s)"
    if result.timed_out:
        caveats.append(f"nmap was stopped at the {round(timeout)}s stage time limit: its output was truncated after "
                       f"{reported} and the rest of the target was not scanned, so results are partial.")
    elif scan.truncated:
        caveats.append(f"nmap output was truncated after {reported}, so results are partial.")
    if scan.timed_out_hosts:
        caveats.append(f"{len(scan.timed_out_hosts)} host(s) hit the {host_timeout}s host timeout, so nmap reported "
                       f"no ports for them: {_host_list(scan.timed_out_hosts)}.")
    if caveats:
        caveats.append("Increase the time budget or reduce top_ports.")
    if not scan.ports and scan.hosts_up == 0:
        caveats.append("Host appears down or fully filtered: no open ports in the probed range.")
    return caveats


def _host_list(hosts: list[str], limit: int = 5) -> str:
    """Up to `limit` host labels, then "and N more", so a note about a large range stays readable."""
    shown = ", ".join(hosts[:limit])
    extra = len(hosts) - limit
    return f"{shown} and {extra} more" if extra > 0 else shown


def _address_families(hostname: str) -> set[int]:
    """The address families (socket.AF_INET, socket.AF_INET6) a hostname resolves to; empty when it does not
    resolve. The question goes to the system resolver, the same one Nmap asks a moment later."""
    try:
        return {info[0] for info in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)}
    except OSError:  # socket.gaierror is an OSError: the name does not resolve, or there is no resolver
        return set()


def _scan_over_ipv6(target: str) -> bool:
    """True when nmap needs its -6 flag: an IPv6 address or block, or a hostname with only IPv6 records.

    Nmap resolves a name over IPv4 unless told otherwise, so without the flag a name that has only AAAA
    records fails as "Failed to resolve". A name with both kinds of record is scanned over IPv4.
    """
    if is_ipv6_target(target):
        return True
    if not is_hostname(target):
        return False
    families = _address_families(target)
    return socket.AF_INET6 in families and socket.AF_INET not in families


# --- Stage 2: web fingerprinting (WhatWeb) --------------------------------------------------------

def _first_stage_failed(run: Run, stage: StageResult) -> bool:
    """True when an earlier first stage failed: the run fails, and a later stage records that it did not run
    rather than a result such as "no web services were discovered", which no stage produced."""
    return bool(run.stages) and run.stages[0] is not stage and run.stages[0].status == "failed"


def stage_web_fingerprint(manager: RunManager, run: Run, request: ExecuteRequest, stage: StageResult,
                          context: StageContext, timeout: float) -> None:
    """Identify the software behind every web service. Writes run.web and context["web"].

    The stage fails only when no URL answered at all; a partial answer completes with notes.
    """
    if _first_stage_failed(run, stage):
        _stop_stage(manager, run, stage, "skipped", "The first stage failed, so WhatWeb did not run.")
        return
    targets = _web_targets(run, context)
    if not targets:
        _stop_stage(manager, run, stage, "skipped", "No web services were discovered, nothing to fingerprint.")
        return
    profile = profile_for_run("whatweb", run.profiles)
    if run.mode == "simulated":
        findings = [simulate_web(port) for port in targets]
        stage.command = (f"whatweb --color=never {profile.flags} --follow-redirect=same-site --log-json=<file> "
                         "<url>  (simulated)")
        stage.status = "simulated"
        manager.add_log(run, f"SIMULATED whatweb on {len(findings)} URL(s)")
    else:
        findings = _run_whatweb(manager, run, stage, context, targets, timeout, profile)
        if findings is None:
            return  # WhatWeb is not installed; the stage has been marked failed
    run.web = findings
    context["web"] = findings
    context["fingerprinted"] = True  # even when it recorded nothing: Nikto then has no URL that answered
    _note_web_cap(stage, context)


def _note_web_cap(stage: StageResult, context: StageContext) -> None:
    """A web stage that ran on fewer services than the port scan found says so and is partial: the services
    beyond MAX_WEB_TARGETS were never probed, so a technology or finding missing from them is not evidence
    of its absence."""
    dropped = context.get("web_dropped", 0)
    if dropped and stage.status in {"completed", "simulated"}:
        notes = [stage.error] if stage.error else []
        notes.append(f"{dropped} web service(s) beyond the limit of {MAX_WEB_TARGETS} per run were not probed")
        stage.error = join_notes(notes)
        stage.partial = True


def _run_whatweb(manager: RunManager, run: Run, stage: StageResult, context: StageContext,
                 targets: list[PortFinding], timeout: float,
                 profile: ToolProfile | None = None) -> list[WebFinding] | None:
    """Probe each web service with WhatWeb while the time budget lasts. None when WhatWeb is not installed.

    `profile` sets the aggression level (1, WhatWeb's stealthy mode, by default); redirects are limited to
    the same site at every level, so the probes stay on the authorised host.
    """
    binary = _require_binary(manager, run, stage)
    if binary is None:
        return None
    profile = profile or profile_for_run("whatweb", run.profiles)
    findings: list[WebFinding] = []
    commands: list[str] = []
    failures: list[str] = []    # URLs that gave no HTTP response, with the reason
    cut_short: list[str] = []   # URLs that answered, but whose probe was stopped before it finished
    not_probed: list[str] = []  # URLs whose probe could not start or was stopped before any answer
    skipped = 0
    gaps = 0  # URLs WhatWeb did not fully examine: killed at the per-URL limit, or the process could not start
    stage_end = _stage_end(context, timeout)
    for index, port in enumerate(targets):
        url = parsers.url_for(port, _probe_host(run))
        per_url = _time_for_next_url(context, stage_end, timeout, len(targets), MIN_WHATWEB_SECONDS)
        if per_url is None:
            skipped = len(targets) - index
            manager.add_log(run, f"time budget exhausted; skipping {skipped} remaining URL(s)")
            break
        path = _temp_path("whatweb-")
        command = [binary, "--color=never", *profile.args, "--follow-redirect=same-site", f"--log-json={path}", url]
        commands.append(" ".join([*command[:-2], "--log-json=<file>", url]))
        manager.add_log(run, f"whatweb: {url}")
        result = _start_tool(command, timeout=per_url, context=context)
        stage.raw_output_chars += len(result.stdout)
        finding = parsers.parse_whatweb_json(_read_and_remove(path), url, parsers.host_address(port.host),
                                             port.port)
        if result.timed_out:
            # WhatWeb logs a URL as soon as it answers, so a probe killed at its limit may already have
            # recorded the response: that URL is reachable, but its fingerprint may be incomplete.
            if finding.reachable:
                cut_short.append(f"{url}: probe stopped at its {int(per_url)}s limit after a response")
            else:
                failures.append(f"{url}: timed out after {int(per_url)}s")
            gaps += 1
        elif result.exit_code == START_FAILED_EXIT_CODE:
            # WhatWeb could not start, or the server's shutdown stopped it: no complete probe was made, so
            # this says nothing about whether the URL answers (it is a gap, not a result).
            gaps += 1
            if not finding.reachable:
                # Nothing is recorded for such a URL: "no HTTP response" would be a result it never had.
                not_probed.append(f"{url}: {result.stderr}")
                continue
            cut_short.append(f"{url}: answered, then {result.stderr}")
        elif not finding.reachable:
            detail = (result.stderr or result.stdout).strip()[:120] or f"exit {result.exit_code}"
            failures.append(f"{url}: no HTTP response ({detail})")
        findings.append(finding)
    stage.command = "\n".join(commands)

    reachable = sum(1 for f in findings if f.reachable)
    if skipped and not findings and not not_probed:
        _stop_stage(manager, run, stage, "failed", f"The time budget ran out before WhatWeb could probe any of "
                                                   f"the {skipped} URL(s).")
    elif (findings or not_probed) and reachable == 0:
        # Every URL that was probed gave no answer. When some were not probed (could not start, or the budget
        # ran out), the reason says so: those URLs prove nothing, and _highlights() reads the difference.
        not_examined = (["not probed: " + "; ".join(not_probed)[:200]] if not_probed else []) + \
                       ([f"{skipped} URL(s) skipped because the time budget ran out"] if skipped else [])
        if failures and not_examined:
            reason = f"{WHATWEB_NO_RESPONSE} it probed: " + "; ".join(failures)[:400] + "; " + "; ".join(not_examined)
        elif failures:
            reason = f"{WHATWEB_NO_RESPONSE}: " + "; ".join(failures)[:600]
        else:
            reason = "WhatWeb could not probe any web service: " + "; ".join(not_probed)[:600]
            if skipped:
                reason += f"; {skipped} URL(s) skipped because the time budget ran out"
        _stop_stage(manager, run, stage, "failed", reason)
    else:
        stage.status = "completed"
        notes = []
        if failures:
            notes.append(f"{len(failures)} of {len(findings)} URL(s) did not respond: " + "; ".join(failures)[:400])
        if not_probed:
            notes.append(f"{len(not_probed)} URL(s) could not be probed: " + "; ".join(not_probed)[:400])
        if cut_short:
            notes.append(f"{len(cut_short)} URL(s) answered but the probe was stopped early, so the "
                         "fingerprint may be incomplete: " + "; ".join(cut_short)[:400])
        if skipped:
            notes.append(f"{skipped} URL(s) skipped because the time budget ran out.")
        stage.error = join_notes(notes)
        # A URL that gave no HTTP response is a result (recorded as unreachable). A URL that could not be probed
        # fully, or at all, is a gap, like the URLs skipped when the budget ran out.
        stage.partial = bool(skipped or gaps)
        manager.add_log(run, f"whatweb: {sum(len(f.technologies) for f in findings)} technologies across "
                             f"{reachable} reachable URL(s)")
    return findings


# --- Stage 3: web vulnerability scan (Nikto) ------------------------------------------------------

def stage_web_vuln_scan(manager: RunManager, run: Run, request: ExecuteRequest, stage: StageResult,
                        context: StageContext, timeout: float) -> None:
    """Check the web services for dangerous files, outdated software and misconfigurations. Writes run.vulns.

    When the fingerprint stage ran, only URLs that answered it are scanned: a URL that gave no HTTP
    response would only use up Nikto's long time budget.
    """
    if _first_stage_failed(run, stage):
        _stop_stage(manager, run, stage, "skipped", "The first stage failed, so Nikto did not run.")
        return
    targets, reason = _web_targets_that_answered(run, context)
    if reason:
        _stop_stage(manager, run, stage, "skipped", reason)
        return
    profile = profile_for_run("nikto", run.profiles)
    if run.mode == "simulated":
        vulns = [vuln for port in targets for vuln in simulate_vulns(port, profile.key)]
        tuning = f" {profile.flags}" if profile.args else ""
        # The per-URL slice a live run with this budget would pass (see _time_for_next_url).
        per_url = int(max(MIN_NIKTO_SECONDS, timeout / len(targets)))
        stage.command = (f"nikto -h <url>{tuning} -Format json -output <file> -maxtime {per_url}s "
                         "-nointeractive -ask no  (simulated)")
        stage.status = "simulated"
        manager.add_log(run, f"SIMULATED nikto: {len(vulns)} finding(s)")
    else:
        vulns = _run_nikto(manager, run, stage, context, targets, timeout, profile)
        if vulns is None:
            return  # Nikto is not installed; the stage has been marked failed
    run.vulns = vulns
    _note_web_cap(stage, context)


def _web_targets_that_answered(run: Run, context: StageContext) -> tuple[list[PortFinding], str | None]:
    """The web services the stages after WhatWeb probe (Nikto, and custom tools that run per URL), or ([], the
    reason) when there are none. When the fingerprint stage ran, only URLs that answered it count."""
    targets = _web_targets(run, context)
    if context.get("fingerprinted") or context.get("web"):
        web = context.get("web", [])
        reachable_urls = {w.url for w in web if w.reachable}
        probed_urls = {w.url for w in web}
        answered = [p for p in targets if parsers.url_for(p, _probe_host(run)) in reachable_urls]
        unprobed = [p for p in targets if parsers.url_for(p, _probe_host(run)) not in probed_urls]
        if not answered and unprobed:
            # WhatWeb never got to these URLs (the budget ran out or it could not start), so nothing is known
            # about whether they answer: "no reachable web services" would be a result no probe produced.
            return [], ("WhatWeb could not probe any web service, so no URL is known to answer; nothing to scan."
                        if not web else
                        f"No web service answered WhatWeb, and {len(unprobed)} URL(s) could not be probed; "
                        "nothing to scan.")
        targets = answered
    if not targets:
        return [], "No reachable web services, nothing to scan."
    return targets, None


def _run_nikto(manager: RunManager, run: Run, stage: StageResult, context: StageContext,
               targets: list[PortFinding], timeout: float,
               profile: ToolProfile | None = None) -> list[VulnFinding] | None:
    """Scan each web service with Nikto while the time budget lasts. None when Nikto is not installed.

    `profile` may narrow the scan to some of Nikto's test categories (-Tuning); the default runs them all.
    """
    binary = _require_binary(manager, run, stage)
    if binary is None:
        return None
    profile = profile or profile_for_run("nikto", run.profiles)
    vulns: list[VulnFinding] = []
    commands: list[str] = []
    failures: list[str] = []   # URLs Nikto produced nothing for, with the reason
    cut_short: list[str] = []  # URLs Nikto reported findings for, but did not examine completely
    successes = skipped = 0
    stage_end = _stage_end(context, timeout)
    for index, port in enumerate(targets):
        url = parsers.url_for(port, _probe_host(run))
        per_url = _time_for_next_url(context, stage_end, timeout, len(targets), MIN_NIKTO_SECONDS)
        if per_url is None:
            skipped = len(targets) - index
            manager.add_log(run, f"time budget exhausted; skipping {skipped} remaining URL(s)")
            break
        path = _temp_path("nikto-")
        command = [binary, "-h", url, *profile.args, "-Format", "json", "-output", path,
                   "-maxtime", f"{int(per_url)}s", "-nointeractive", "-ask", "no"]
        commands.append(" ".join(command).replace(path, "<file>"))
        manager.add_log(run, f"nikto: {url}")
        # -maxtime makes Nikto stop by itself; the 5 extra seconds on the subprocess timeout let it write its
        # JSON report before it would be killed.
        result = _start_tool(command, timeout=per_url + 5, context=context)
        stage.raw_output_chars += len(result.stdout)
        report = _read_and_remove(path)
        is_json = parsers.nikto_output_is_json(report)
        if is_json:
            found = parsers.parse_nikto_json(report, url)
        elif result.stdout.strip():
            found = parsers.parse_nikto_text(result.stdout, url)  # no report: use what Nikto printed
        else:
            reason = "timed out" if result.timed_out else (result.stderr.strip()[:120] or "no output")
            failures.append(f"{url}: {reason}")
            continue
        # A Nikto killed at its time limit examined only part of the URL, and Nikto prints why it stopped
        # early (too many errors, its -maxtime, no web server) even when it also wrote a report: such a URL is
        # never recorded as examined and clean. Its findings are kept, and the stage is marked partial.
        if result.timed_out:
            stopped: str | None = f"stopped at its {int(per_url)}s time limit"
        else:
            stopped = parsers.nikto_stopped_early(result.stdout)
            if stopped is None and not is_json and not found:
                stopped = parsers.nikto_text_problem(result.stdout)  # the banner alone
        if stopped is None:
            successes += 1
        elif found or parsers.nikto_reached_maxtime(result.stdout):
            # Findings were reported, or Nikto ran its tests until its own -maxtime: the URL was examined,
            # only not completely.
            successes += 1
            cut_short.append(f"{url}: {stopped}")
        else:
            failures.append(f"{url}: {stopped}")
        vulns.extend(found)
    stage.command = "\n".join(commands)

    attempted = successes + len(failures)
    if skipped and not attempted:
        _stop_stage(manager, run, stage, "failed", f"The time budget ran out before Nikto could scan any of the "
                                                   f"{skipped} URL(s).")
    elif attempted and successes == 0:
        reason = "Nikto produced no results for any URL: " + "; ".join(failures)[:600]
        if skipped:
            reason += f"; {skipped} URL(s) skipped because the time budget ran out"
        _stop_stage(manager, run, stage, "failed", reason)
    else:
        stage.status = "completed"
        notes = []
        if failures:
            notes.append(f"{len(failures)} of {attempted} URL(s) failed: " + "; ".join(failures)[:400])
        if cut_short:
            notes.append(f"{len(cut_short)} URL(s) were not examined completely, so findings may be missing: "
                         + "; ".join(cut_short)[:400])
        if skipped:
            notes.append(f"{skipped} URL(s) skipped because the time budget ran out.")
        stage.error = join_notes(notes)
        # Nikto only scans URLs that answered WhatWeb, so a URL it produced nothing for was not examined.
        stage.partial = bool(skipped or failures or cut_short)
        manager.add_log(run, f"nikto: {len(vulns)} finding(s)")
    return vulns


# --- Stage 4: custom tools ------------------------------------------------------------------------

def stage_custom_tool(manager: RunManager, run: Run, request: ExecuteRequest, stage: StageResult,
                      context: StageContext, timeout: float) -> None:
    """Run one custom tool (registered on the Custom tools page, see tools/custom.py) and keep what it printed
    in run.custom_outputs. A per-URL tool probes the same URLs as Nikto. The output is never parsed or scored.
    A live stage given no time (see _stage_budgets) still runs on the time the built-in stages left over; when
    none was left, it fails with the time budget that would be enough."""
    tool = run.custom_tools.get(stage.tool)
    if tool is None:
        _stop_stage(manager, run, stage, "failed", f"No definition of {stage.tool} was recorded with this run.")
        return
    if run.stages and run.stages[0].status == "failed":
        _stop_stage(manager, run, stage, "skipped", f"The first stage failed, so {tool.name} did not run.")
        return
    if tool.scope == "url":
        ports, reason = _web_targets_that_answered(run, context)
        if reason:
            _stop_stage(manager, run, stage, "skipped", reason)
            return
        urls = [parsers.url_for(port, _probe_host(run)) for port in ports]
    else:
        urls = [""]  # once, against the run's target
    if run.mode == "simulated":
        for url in urls:
            command = build_command(tool.program, tool.args, run.target, url)
            _keep_output(manager, run, tool.name, url or run.target, CommandResult(
                command=command, exit_code=None, stdout=simulate_custom_output(tool.name, " ".join(command)),
                stderr="", duration_seconds=0.0, started=False), ended="simulated")
        stage.command = " ".join([tool.program, *tool.args]) + "  (simulated)"
        stage.status = "simulated"
        manager.add_log(run, f"SIMULATED {tool.name}: {len(urls)} call(s)")
    else:
        _run_custom(manager, run, stage, context, tool, urls, timeout)
    if tool.scope == "url":
        _note_web_cap(stage, context)


def _run_custom(manager: RunManager, run: Run, stage: StageResult, context: StageContext, tool: CustomTool,
                urls: list[str], timeout: float) -> None:
    """Call the tool once per URL (or once on the target, when `urls` is [""]) while the time budget lasts.

    Each call is limited by the tool's own time limit, by its share of the stage, and by the run's deadline
    minus the time a kill needs to drain the pipes. A non-zero exit code is not a failure: the output is kept.
    When the server shuts down, the call it stopped keeps what it printed, and the calls it kept from starting
    are counted in the stage's note.
    """
    path, problem = find_program(tool.program)
    if problem or path is None:
        _stop_stage(manager, run, stage, "failed", problem or (
            f"{tool.name} is not installed: {tool.program} was not found. Install it, register its full path, or "
            "use simulation mode."))
        return
    commands: list[str] = []
    not_started: list[str] = []  # calls that could not start, with the reason
    cut_short: list[str] = []    # calls stopped at their time limit
    flooded = over_limit = skipped = ran = 0
    shut_down = not_run = 0  # calls the server's shutdown stopped, and calls it kept from starting
    run_cut = {"part": 0, "none": 0}  # calls of which the run-wide output limit kept only part, or nothing
    stage_end = _stage_end(context, timeout)
    for index, url in enumerate(urls):
        if context.get("interrupted"):  # the server is shutting down: no further call may start
            not_run = len(urls) - index
            break
        per_call = _time_for_next_url(context, stage_end, timeout, len(urls), MIN_CUSTOM_SECONDS)
        if per_call is not None:
            per_call = min(per_call, tool.timeout_seconds, math.floor(_remaining(context) - DRAIN_SECONDS))
        if per_call is None or per_call < MIN_CUSTOM_SECONDS:
            skipped = len(urls) - index
            manager.add_log(run, f"time budget exhausted; skipping {skipped} remaining call(s) of {tool.name}")
            break
        where = url or run.target
        command = build_command(path, tool.args, run.target, url)
        commands.append(" ".join(command))
        manager.add_log(run, f"{tool.name}: {where}")
        result = _start_tool(command, timeout=per_call, context=context, max_chars=STDOUT_CHARS)
        stage.raw_output_chars += len(result.stdout)
        kept = _keep_output(manager, run, tool.name, where, result)
        if kept.ended == "not_started" and context.get("interrupted"):
            not_run = len(urls) - index  # refused because the server is shutting down: counted with the rest
            break
        ran += 1
        if tool.scope == "target":
            stage.exit_code = kept.exit_code  # None unless the program exited by itself
        if kept.run_limit:
            run_cut["part" if kept.stdout or kept.stderr else "none"] += 1
        # A program that exits 127 ("command not found") without printing anything did not run either.
        if kept.ended == "not_started" or (kept.exit_code == START_FAILED_EXIT_CODE and not result.stdout):
            not_started.append(f"{where}: {result.stderr.strip()[:120] or 'could not start'}")
        elif kept.ended == "shutdown":
            shut_down += 1
        elif kept.ended == "time_limit":
            cut_short.append(f"{where}: stopped at its {int(per_call)}s limit")
        elif kept.ended == "output_limit":
            flooded += 1
        elif result.truncated:  # it had already exited by itself when its output passed the limit
            over_limit += 1
    stage.command = "\n".join(commands)

    shutdown_note = f"{not_run} call(s) were not started because the server shut down"
    if not ran:
        if not_run:
            _stop_stage(manager, run, stage, "skipped", SHUTDOWN_REASON, log_message=f"{tool.name}: {shutdown_note}")
        else:
            # With a share of 0 (see _stage_budgets) a call still runs on the time the built-in stages left over;
            # when none was left, say which budget would give the custom tools their minimum.
            needed = _custom_budget_needed(run.tools)
            short = context["budget"] < needed if "budget" in context else timeout <= 0
            hint = f" Raise the run's timeout to at least {needed} seconds." if short else ""
            _stop_stage(manager, run, stage, "failed", f"The time budget ran out before {tool.name} could run.{hint}")
        return
    if len(not_started) == ran:
        reason = f"{tool.name} could not run: " + "; ".join(not_started)[:600]
        _stop_stage(manager, run, stage, "failed", join_notes([reason, shutdown_note]) if not_run else reason)
        return
    stage.status = "completed"
    notes = []
    if not_started:
        notes.append(f"{len(not_started)} call(s) could not start: " + "; ".join(not_started)[:300])
    if shut_down:
        notes.append(f"{shut_down} call(s) were stopped because the server shut down, so their output is incomplete")
    if not_run:
        notes.append(shutdown_note)
    if cut_short:
        notes.append(f"{len(cut_short)} call(s) were stopped at their time limit, so their output is incomplete: "
                     + "; ".join(cut_short)[:300])
    if flooded:
        notes.append(f"{flooded} call(s) printed more than {STDOUT_CHARS:,} characters and were stopped, so their "
                     "output is incomplete")
    if over_limit:
        # "At most": the run-wide limit may have kept less of a call, or none of it (the note after this one says so).
        notes.append(f"{over_limit} call(s) printed more than {STDOUT_CHARS:,} characters on standard output or on "
                     f"standard error, so at most the first {STDOUT_CHARS:,} characters of each were kept")
    if skipped:
        notes.append(f"{skipped} call(s) skipped because the time budget ran out")
    # Output the run-wide limit did not keep is a gap in what HybridSec stored, not in what the tool did, so it is
    # a note only. A custom stage never makes the run partial anyway (see _has_gaps).
    stage.partial = bool(notes)
    counts = [f"{count} call(s) kept {what} of their output"
              for count, what in ((run_cut["part"], "only part"), (run_cut["none"], "none")) if count]
    if counts:
        notes.append(" and ".join(counts) + f", because the run's custom-output limit ({RUN_OUTPUT_CHARS:,} "
                                            "characters) was reached")
    stage.error = join_notes(notes)
    manager.add_log(run, f"{tool.name}: {ran} call(s) finished")


def _call_ended(result: CommandResult) -> str:
    """How a custom tool call ended, as CustomToolOutput.ended records it (a simulated call is never run)."""
    if not result.started:
        return "not_started"
    if result.interrupted:
        return "shutdown"
    if result.timed_out:
        return "time_limit"
    if result.truncated and result.exit_code is None:  # run_command stopped it for printing too much
        return "output_limit"
    return "exited"


def _keep_output(manager: RunManager, run: Run, tool_name: str, target: str, result: CommandResult,
                 ended: str | None = None) -> CustomToolOutput:
    """Record one call's output: cleaned (no colour codes or control characters) and capped per call and per run.

    `ended` says how the call ended (see CustomToolOutput.ended); by default it is read from the result. The exit
    code is kept only when the program exited by itself. Returns the record: its run_limit says whether the
    run-wide limit (RUN_OUTPUT_CHARS) kept only part of what the per-call limits allow, or none of it.
    """
    ended = ended or _call_ended(result)
    stored = sum(len(o.stdout) + len(o.stderr) for o in run.custom_outputs)  # only this worker thread appends
    room = max(0, RUN_OUTPUT_CHARS - stored)
    stdout, stderr = clean_output(result.stdout), clean_output(result.stderr)
    call_out, call_err = stdout[:STDOUT_CHARS], stderr[:STDERR_CHARS]  # what the per-call limits keep
    kept_out = call_out[:room]
    kept_err = call_err[:room - len(kept_out)]
    output = CustomToolOutput(
        tool=tool_name, target=target, command=" ".join(result.command),
        exit_code=result.exit_code if ended == "exited" else None, timed_out=ended == "time_limit", ended=ended,
        duration_seconds=result.duration_seconds, stdout=kept_out, stderr=kept_err,
        truncated=result.truncated or len(kept_out) < len(stdout) or len(kept_err) < len(stderr),
        run_limit=len(kept_out) < len(call_out) or len(kept_err) < len(call_err))
    manager.add_output(run, output)
    return output


# Stage name -> handler. Every handler takes (manager, run, request, stage, context, stage_timeout), fills in
# `stage` and its own part of `run`, and passes its results on through `context`.
STAGE_HANDLERS: dict[str, Callable[..., None]] = {
    "port_scan": stage_port_scan,
    "web_fingerprint": stage_web_fingerprint,
    "web_vuln_scan": stage_web_vuln_scan,
    CUSTOM_STAGE: stage_custom_tool,
}


# --- Time budget ----------------------------------------------------------------------------------

def _stage_budgets(tools: list[str], total: int) -> dict[str, float]:
    """Split the run's time budget between its stages in proportion to STAGE_TIME_WEIGHTS.

    The custom tools of a run share one weight, CUSTOM_TOOLS_WEIGHT, so they take a bounded share from the
    built-in stages' shares, but never the minimum times those stages need. The built-in stages come first: one
    whose proportional share falls below the time its tool needs for a single probe (see STAGE_MIN_SECONDS) is
    lifted to that minimum whenever the built-in minimums together fit the total, and the difference is taken
    from the built-in stages with the most slack, then from the custom tools' share. Otherwise a short budget
    with three tools would give Nikto a share it can never use, and the stage would skip every URL. The custom
    stages split what is left equally, and a custom stage is lifted to its own 10 s minimum only from that custom
    share, never from a built-in stage. A share still below its minimum is raised to it without taking time from
    another stage, so the shares may add up to more than the total (when the built-in minimums do not fit it, or
    the custom stages' share is too small for theirs); the run-wide deadline still caps the later stages.

    When the total minus the built-in stages' minimums is less than MIN_CUSTOM_SECONDS, the budget cannot promise a
    custom call its minimum, so the custom stages get no share (0) and the built-in stages get exactly the shares
    they would have without custom tools: no built-in stage is cut for time a custom tool might not use. A custom
    call then runs only on what the built-in stages left over before the run deadline, and when nothing is left the
    stage names the budget that would be enough (_custom_budget_needed).
    """
    built_in = [t for t in tools if t in STAGE_TIME_WEIGHTS]
    custom = [t for t in tools if t not in STAGE_TIME_WEIGHTS]  # custom tools share CUSTOM_TOOLS_WEIGHT
    if custom and total - sum(STAGE_MIN_SECONDS[t] for t in built_in) < MIN_CUSTOM_SECONDS:
        alone = _stage_budgets(built_in, total)
        return {t: alone.get(t, 0.0) for t in tools}
    weights = {t: STAGE_TIME_WEIGHTS.get(t, CUSTOM_TOOLS_WEIGHT / max(1, len(custom))) for t in tools}
    minimums = {t: STAGE_MIN_SECONDS.get(t, 10.0) for t in tools}
    scale = sum(weights.values()) or 1.0
    shares = {t: total * w / scale for t, w in weights.items()}
    custom_share = sum(shares[t] for t in custom)
    if sum(minimums[t] for t in built_in) <= total:
        for tool in built_in:
            deficit = minimums[tool] - shares[tool]
            if deficit <= 0:
                continue
            shares[tool] = minimums[tool]
            for donor in sorted((d for d in built_in if d != tool), key=lambda d: shares[d] - minimums[d],
                                reverse=True):
                given = min(deficit, max(0.0, shares[donor] - minimums[donor]))
                shares[donor] -= given
                deficit -= given
            custom_share = max(0.0, custom_share - deficit)  # the rest comes from the custom tools' share
    # Every custom tool has the same weight and the same minimum, so an equal split is also the split that lifts
    # one from the others' slack; when the share is too small for all of them, the run deadline caps the excess.
    for tool in custom:
        shares[tool] = custom_share / len(custom)
    return {t: max(minimums[t], share) for t, share in shares.items()}


def _custom_budget_needed(tools: list[str]) -> int:
    """The time budget, in whole seconds, at which every custom tool of a workflow gets its MIN_CUSTOM_SECONDS from
    _stage_budgets: the built-in stages' minimums plus that minimum per custom tool, or the budget whose proportional
    custom share (CUSTOM_TOOLS_WEIGHT) gives each custom tool that minimum, whichever is larger."""
    built_in = [t for t in tools if t in STAGE_TIME_WEIGHTS]
    count = max(1, len(tools) - len(built_in))  # the custom tools
    minimums = sum(STAGE_MIN_SECONDS[t] for t in built_in) + MIN_CUSTOM_SECONDS * count
    weights = sum(STAGE_TIME_WEIGHTS[t] for t in built_in) + CUSTOM_TOOLS_WEIGHT  # the scale _stage_budgets uses
    proportional = MIN_CUSTOM_SECONDS * count * weights / CUSTOM_TOOLS_WEIGHT
    return math.ceil(round(max(minimums, proportional), 6))  # rounded first, so 60.0000001 is still 60


# --- Summary and risk score -----------------------------------------------------------------------

# Risk points per finding, also used to rank findings for the highlights.
SEVERITY_WEIGHT = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
# Services that should rarely be reachable from outside: remote administration, file sharing and databases.
RISKY_SERVICES = {"telnet", "ftp", "smb", "microsoft-ds", "netbios-ssn", "rdp", "ms-wbt-server", "vnc", "mysql",
                  "postgresql", "redis", "mongodb", "snmp", "rpcbind", "msrpc", "x11"}
# Technologies whose disclosed version lets an attacker look up known vulnerabilities.
VERSION_SENSITIVE = {"wordpress", "php", "apache", "nginx", "jquery", "drupal", "joomla", "openssl", "iis",
                     "microsoft-iis", "tomcat", "apache tomcat", "jetty", "express", "django", "laravel"}


def summarize(run: Run, hosts_up: int | None = None, *, failed: bool = False) -> RunSummary:
    """Headline numbers, a 0-100 risk score and up to eight highlights for a run.

    Only web services that answered count. `hosts_up` is Nmap's own count when the run had a port scan; a
    host is also known to be up when a web service on it answered (or, in a Nikto-only workflow, when Nikto
    examined it), which is how a workflow without a port scan counts its hosts. `partial` is set when the
    run completes with gaps (see _has_gaps), so every view of the run can say so. `failed` says the run
    ended as failed although its first stage did not fail (the server shut down or restarted): such a run
    is neither partial nor given a highlight that would read as a clean result.
    """
    reachable_web = [w for w in run.web if w.reachable]
    hosts = {parsers.host_address(p.host) for p in run.ports} | {w.host for w in reachable_web}
    if not hosts and (run.vulns or _nikto_examined(run)):
        # A Nikto-only workflow: Nikto examined (or reported findings on) the target's standard web ports, so
        # the target answered. Such a workflow has exactly one target host (a range needs a port scan).
        hosts = {run.target}
    if hosts_up is None:
        hosts_up = len(hosts)
    hosts_up = max(hosts_up, len(hosts))  # never fewer live hosts than hosts seen with ports or web services
    return RunSummary(
        hosts_up=hosts_up,
        open_ports=len(run.ports),
        web_services=len(reachable_web),
        technologies=sum(len(w.technologies) for w in reachable_web),
        vulnerabilities=len(run.vulns),
        risk_score=_risk_score(run, reachable_web),
        highlights=_highlights(run, reachable_web, failed=failed)[:8],
        partial=not failed and _has_gaps(run.stages),
    )


def _nikto_examined(run: Run) -> bool:
    """True when the run's Nikto stage examined at least one URL (a completed stage did, by definition)."""
    return any(s.tool == "nikto" and s.status in {"completed", "simulated"} for s in run.stages)


def _has_gaps(stages: list[StageResult]) -> bool:
    """True when a run that completes is known to be incomplete: a stage completed with partial results, or a
    later stage failed, so its part of the picture is missing. A run whose first stage failed is not "partial":
    its status says it failed, and the reports and the comparison treat it that way. Custom tools do not count:
    their output is not part of the findings this flag describes (a failed one still shows in run.error)."""
    if _final_outcome(stages)[0] != "completed":
        return False
    return any((stage.partial or stage.status == "failed") and stage.stage != CUSTOM_STAGE for stage in stages)


def _risk_score(run: Run, reachable_web: list[WebFinding]) -> int:
    """A transparent heuristic, not a CVSS score. Each signal is capped so that none dominates: up to 30
    points for open ports (3 each), 20 for web services (5 each), 20 for disclosed versions (2 each) and
    30 for findings weighted by severity."""
    score = min(30, len(run.ports) * 3) + min(20, len(reachable_web) * 5)
    versioned = sum(1 for w in reachable_web for t in w.technologies if t.get("version"))
    score += min(20, versioned * 2)
    score += min(30, sum(SEVERITY_WEIGHT.get(v.severity, 0) for v in run.vulns))
    return max(0, min(100, score))


def _highlights(run: Run, reachable_web: list[WebFinding], failed: bool = False) -> list[str]:
    """Notable observations: up to three critical, high or medium findings (most severe first), then up to
    four exposed management or database services, then disclosed versions of version-sensitive software."""
    # Most severe first, so the eight-item cap never hides a critical or high finding behind version notes.
    highlights: list[str] = []
    seen_findings: set[str] = set()
    for vuln in sorted(run.vulns, key=lambda v: -SEVERITY_WEIGHT.get(v.severity, 0)):
        # The same finding on several URLs (nginx outdated on :80 and :443) is one observation, not three.
        if vuln.severity not in {"critical", "high", "medium"} or vuln.description in seen_findings:
            continue
        seen_findings.add(vuln.description)
        highlights.append(f"[{vuln.severity}] {vuln.description[:120]}")
        if len(seen_findings) == 3:
            break
    risky = [p for p in run.ports if p.service.split("/")[-1] in RISKY_SERVICES]
    highlights.extend(
        f"Management or database service exposed: {port.service} on port {port.port}" for port in risky[:4]
    )
    seen_versions: set[tuple[str, str]] = set()
    for web in reachable_web:
        for tech in web.technologies:
            name, version = str(tech.get("name", "")), tech.get("version")
            if version and name.lower() in VERSION_SENSITIVE and (name.lower(), version) not in seen_versions:
                seen_versions.add((name.lower(), version))
                highlights.append(f"{name} {version} disclosed at {web.url}")
    if not highlights and not failed:
        # One sentence about what the run established. A stage that failed or never ran established
        # nothing, so a failed port scan never reads as a clean host (the run's status says it failed).
        port_scan = next((s for s in run.stages if s.stage == "port_scan"), None)
        web_probe = next((s for s in run.stages if s.stage == "web_fingerprint"), None)
        if run.ports or reachable_web or _nikto_examined(run):
            highlights.append(_no_exposures(run))
        elif port_scan is not None:
            if port_scan.status in {"completed", "simulated"}:
                highlights.append("No open ports were found in the probed range.")
        elif web_probe is not None and (web_probe.error or "").startswith(WHATWEB_NO_RESPONSE + ":"):
            # Only when every URL was probed and none answered; a URL that could not be probed proves nothing.
            highlights.append("No reachable web service was found on the standard ports "
                              "(no port scan in this workflow).")
    return highlights


def _no_exposures(run: Run) -> str:
    """The highlight of a run whose results hold nothing notable. Custom tool output is never examined, so with
    custom tools the sentence names the built-in tools that ran, and says so."""
    if not any(s.stage == CUSTOM_STAGE for s in run.stages):
        return "No notable exposures were identified with the selected tools."
    names = [TOOLS[s.tool].display_name for s in run.stages
             if s.stage != CUSTOM_STAGE and s.tool in TOOLS and s.status in {"completed", "simulated"}]
    listed = names[-1] if names else "the built-in tools"
    if len(names) > 1:
        listed = ", ".join(names[:-1]) + " and " + listed
    return f"No notable exposures were identified with {listed}; custom tool output is not examined."


# --- Simulation mode ------------------------------------------------------------------------------
# Synthetic but realistic results that demonstrate the pipeline without scanners or network access. They
# are derived from a hash of the target, so the same target always gives the same results, which keeps
# comparisons between simulated runs meaningful; the chosen Nmap and Nikto profiles then shape the detail
# the way they would in a live scan (see simulate_ports and simulate_vulns).

# (port, service, product, version, extra info). The first two are always present.
_SIMULATED_SERVICES = [
    (22, "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6", "Ubuntu Linux; protocol 2.0"),
    (80, "http", "nginx", "1.18.0", ""),
    (443, "ssl/http", "nginx", "1.18.0", ""),
    (3306, "mysql", "MySQL", "8.0.36-0ubuntu0.22.04.1", ""),
    (8080, "http", "Apache Tomcat", "9.0.65", ""),
    (21, "ftp", "vsftpd", "3.0.5", ""),
    (8443, "ssl/https-alt", "Jetty", "9.4.44.v20210927", ""),
    (5432, "postgresql", "PostgreSQL DB", "14.11", ""),
]


def _seed(text: str) -> int:
    """A number derived from `text` that is the same in every process (Python's own hash() is not)."""
    return int(hashlib.sha256(text.encode()).hexdigest()[:8], 16)


def simulate_custom_output(tool_name: str, command: str) -> str:
    """What a simulated run records for a custom tool call: the program is never started (it need not be
    installed), so the text says what would have run. Derived from the command, so it is the same every time."""
    return (f"[simulated] {tool_name} was not started: this run uses simulation mode.\n"
            f"[simulated] It would have run: {command}\n"
            f"[simulated] Sample output id {_seed(command):08x}. Custom tool output is kept as text and never scored.")


# What the "scripts" profile's default NSE scripts would report per service, as "script-id: output" notes.
_SIMULATED_SCRIPT_NOTES = {
    "ssh": "ssh-hostkey: 3072 RSA, 256 ECDSA, 256 ED25519",
    "http": "http-title: Demo Portal",
    "https": "http-title: Demo Portal; ssl-cert: Subject: commonName=demo.lab (valid for 364 more days)",
    "https-alt": "http-title: Jenkins [Jenkins]; ssl-cert: Subject: commonName=jenkins.lab",
    "ftp": "ftp-syst: UNIX Type: L8; ftp-anon: Anonymous FTP login allowed (FTP code 230)",
    "mysql": "mysql-info: Protocol 10, Status: Autocommit",
}


def simulate_ports(target: str, profile: str = "version") -> tuple[list[PortFinding], int]:
    """Simulated Nmap result: SSH and HTTP always, plus services picked by the bits of the target's hash.

    The Nmap profile shapes the detail, as it would in a live scan: the quick profile has no version
    probes, so it names services only; the scripts profile adds the notes the default scripts would print.
    """
    seed = _seed(target)
    host = target.split("/", maxsplit=1)[0]
    if "/" in target:
        # A network address is never a live host: a range shows its first usable address, as a scan would.
        with suppress(ValueError, StopIteration):
            host = str(next(iter(ipaddress.ip_network(target, strict=False).hosts())))
    chosen = _SIMULATED_SERVICES[:2] + [entry for index, entry in enumerate(_SIMULATED_SERVICES[2:], start=2)
                                        if (seed >> index) & 1]
    ports = []
    for port, service, product, version, extra_info in sorted(chosen):
        tunnel = "ssl" if service.startswith("ssl/") else ""
        name = service.split("/")[-1]
        detail = {"product": product, "version": version, "extra": extra_info}
        if profile == "quick":
            detail = {"product": "", "version": "", "extra": ""}
        elif profile == "scripts":
            notes = _SIMULATED_SCRIPT_NOTES.get("https" if tunnel and name == "http" else name, "")
            detail["extra"] = "; ".join(note for note in (extra_info, notes) if note)
        ports.append(PortFinding(host=host, port=port, protocol="tcp", state="open", service=service,
                                 is_web=parsers.is_web_service(port, name, tunnel), **detail))
    return ports, 1


def _simulated_product(port: PortFinding) -> str:
    """The software behind a simulated web port, in lower case. Taken from the port itself when the Nmap stage
    recorded it, else from the catalogue by port number: the quick Nmap profile records no product, and a run
    without a port scan assumes ports 80 and 443, but what WhatWeb and Nikto would find does not depend on
    what Nmap reported, so the sample data must not change with the Nmap profile."""
    if port.product:
        return port.product.lower()
    return next((entry[2] for entry in _SIMULATED_SERVICES if entry[0] == port.port), "").lower()


def simulate_web(port: PortFinding) -> WebFinding:
    """Simulated WhatWeb result that matches the simulated product on the port."""
    url = parsers.url_for(port)
    seed = _seed(url)
    product = _simulated_product(port)
    if "tomcat" in product:
        techs = [{"name": "HTTPServer", "string": "Apache-Coyote/1.1"}, {"name": "Apache Tomcat", "version": "9.0.65"},
                 {"name": "Java", "version": "11"}]
        title = "Apache Tomcat/9.0.65"
    elif "jetty" in product:
        techs = [{"name": "HTTPServer", "string": "Jetty(9.4.44.v20210927)"}, {"name": "Jetty", "version": "9.4.44"}]
        title = "Jenkins [Jenkins]"
    else:
        techs = [{"name": "HTTPServer", "string": "nginx/1.18.0"}, {"name": "nginx", "version": "1.18.0"},
                 {"name": "PHP", "version": "7.4.33"}, {"name": "JQuery", "version": "1.12.4"},
                 {"name": "Bootstrap", "version": "4.6.0"}, {"name": "Cookies", "string": "PHPSESSID"},
                 {"name": "HTML5"}, {"name": "Script", "string": "text/javascript"}]
        if seed % 2:
            techs.append({"name": "WordPress", "version": "5.8.2"})
            techs.append({"name": "MetaGenerator", "string": "WordPress 5.8.2"})
            title = "Demo Corporate Site - Just another WordPress site"
        else:
            techs.append({"name": "Laravel"})
            title = "Demo Portal"
    return WebFinding(url=url, host=parsers.host_address(port.host), port=port.port, status_code=200,
                      title=title, technologies=techs)


def simulate_vulns(port: PortFinding, profile: str = "all") -> list[VulnFinding]:
    """Simulated Nikto findings: two missing security headers everywhere, plus product-specific issues.

    Each product-specific finding belongs to Nikto tuning categories (2 and e for the Tomcat Manager, b for
    outdated software, 1 and e for the WordPress login page); a profile that narrows the scan with -Tuning
    only reports the findings in its categories, as Nikto would. The header checks are not tuned and are
    always reported. Severities come from classify_nikto(), as they do for a live run, so a simulated
    message is graded exactly like the same message from a real Nikto.
    """
    url = parsers.url_for(port)
    # (tuning categories, URL, Nikto's message, reference)
    candidates = [
        ("", url, "The anti-clickjacking X-Frame-Options header is not present.",
         "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"),
        ("", url, "The X-Content-Type-Options header is not set. User agents may MIME-sniff content.",
         "https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/"),
    ]
    product = _simulated_product(port)
    if "tomcat" in product:
        candidates.append(("2e", f"{url}/manager/html",
                           "Tomcat Manager application is reachable. Default credentials should be verified.",
                           "CWE-284"))
    elif "nginx" in product:
        candidates.append(("b", url, "nginx/1.18.0 appears to be outdated (current stable is 1.26.x).",
                           "https://nginx.org/en/security_advisories.html"))
        if _seed(url) % 2:
            candidates.append(("1e", f"{url}/wp-login.php",
                               "WordPress login page is publicly reachable; consider rate limiting and MFA.",
                               "OWASP ASVS 2.2"))
    args = profile_for_run("nikto", {"nikto": profile}).args
    tuning = args[args.index("-Tuning") + 1] if "-Tuning" in args else None
    return [VulnFinding(url=u, severity=parsers.classify_nikto(message), description=message, reference=reference)
            for categories, u, message, reference in candidates
            if tuning is None or not categories or any(c in tuning for c in categories)]


# The single RunManager shared by the API routers (imported as `hybrid.manager`).
manager = RunManager()
