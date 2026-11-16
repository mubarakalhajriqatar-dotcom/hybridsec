"""Pydantic models: the shape of every request and response body, and of the documents stored in SQLite.

FastAPI validates incoming JSON against these models and uses their descriptions to build the Swagger page
at /docs. The planner validates AI output with Plan, the pipeline fills in Run as it executes, and
storage.py saves plans and runs in their JSON form.
"""
from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# --- Tools ----------------------------------------------------------------------------------------

class ToolProfileInfo(BaseModel):
    """One way of using a tool that a run may select: a preset, non-exploitative set of command-line options."""

    key: str = Field(description="Profile identifier to pass in ExecuteRequest.profiles.")
    label: str = Field(description="Short name shown in the dashboard's drop-down.")
    description: str = Field(description="What the profile does and when to pick it.")
    flags: str = Field(description="The options the profile adds to the tool's command line (\"\" for none).")
    default: bool = Field(description="True for the profile used when a request names none.")


class ToolInfo(BaseModel):
    """One supported external tool and whether this machine has it installed."""

    name: str = Field(description="Tool identifier used in requests: nmap, whatweb or nikto.")
    display_name: str = Field(description="Human-readable tool name.")
    category: str = Field(description="Kind of assessment the tool performs.")
    description: str = Field(description="What the tool contributes to a hybrid run.")
    stage: str = Field(description="Pipeline stage the tool runs in.")
    installed: bool = Field(description="True when the tool's executable was found on PATH.")
    path: str | None = Field(default=None, description="Full path of the executable, when installed.")
    version: str | None = Field(default=None, description="Version reported by the tool, when it could be detected.")
    install_hint: str = Field(description="How to install the tool on Linux and on Windows.")
    profiles: list[ToolProfileInfo] = Field(default_factory=list,
                                            description="The profiles a run may choose for this tool, default first.")


# --- Custom tools ---------------------------------------------------------------------------------
# Extra command-line tools the operator registers on the dashboard's Custom tools page (see tools/custom.py for
# the rules). They run after the built-in tools; their output is kept as text, never parsed or scored.

class CustomToolCreate(BaseModel):
    """A custom tool to register."""

    name: str = Field(..., min_length=1, max_length=32,
                      description="Identifier used in ExecuteRequest.tools: 1-32 lower-case letters, digits, - or _, "
                                  "starting with a letter. Not a built-in tool's name.")
    description: str = Field(default="", max_length=300, description="Optional note on what the tool is for.")
    program: str = Field(..., min_length=1, max_length=260,
                         description="Executable name found on PATH (for example curl) or its full path. It must "
                                     "be on the HYBRIDSEC_CUSTOM_PROGRAMS list; shells, interpreters, script files and "
                                     "attack tools are refused.")
    args: list[str] = Field(..., min_length=1, max_length=30,
                            description="Arguments, one list item per argument (no shell, no quoting). Only "
                                        "{target} and {url} are filled in.")
    scope: Literal["target", "url"] = Field(
        ..., description="target: runs once on the run's target ({target}); url: runs once per web URL found by the "
                         "earlier stages ({url}).")
    timeout_seconds: int = Field(default=60, ge=10, le=86400,
                                 description="Time limit per call; the run's time budget may stop a call sooner.")


class CustomTool(CustomToolCreate):
    """A registered custom tool: the stored definition, and the copy a run keeps of it."""

    created_at: datetime = Field(description="When the tool was registered (UTC).")


class CustomToolInfo(CustomTool):
    """A registered custom tool and whether this machine can run it."""

    installed: bool = Field(description="True when the program was found and passes the rules.")
    path: str | None = Field(default=None, description="The file that runs, when found.")
    install_hint: str = Field(default="", description="Why the tool cannot run, or how to install the program; "
                                                      "empty when it is installed.")
    refused: bool = Field(default=False, description="True when the stored definition no longer passes the "
                                                     "registration rules (for example after the allow-list was "
                                                     "shortened); it cannot be part of any run, simulated or live.")
    blocked: bool = Field(default=False, description="True when the program was found but the file it resolves to "
                                                     "is refused (a script, a file on a network share, a file in "
                                                     "HybridSec's own folder, a shell behind a link); install_hint "
                                                     "says why. It cannot run live; simulated runs still record it.")


class CustomToolList(BaseModel):
    """GET /api/tools/custom: the programs that may be registered and the registered tools."""

    allowed_programs: list[str] = Field(description="Programs that may be registered: the HYBRIDSEC_CUSTOM_PROGRAMS "
                                                    "entries as written in .env (or the defaults), without those "
                                                    "that are always refused.")
    tools: list[CustomToolInfo] = Field(description="Registered custom tools, by name.")
    unreadable: list[str] = Field(default_factory=list,
                                  description="Names of stored custom tools whose saved definition can no longer be "
                                              "read (damaged, or written by another version). They still count "
                                              "towards the limit and hold their name; delete them to free both.")


class CustomToolOutput(BaseModel):
    """What one call of a custom tool printed. Kept as text (control characters removed), never parsed."""

    tool: str = Field(description="Custom tool name.")
    target: str = Field(description="The target or web URL the call ran against.")
    command: str = Field(description="The command line that ran, arguments separated by spaces.")
    exit_code: int | None = Field(default=None, description="The program's own exit code; null when it did not "
                                                               "exit by itself (see ended).")
    timed_out: bool = Field(default=False, description="True when the call was stopped at its time limit.")
    ended: Literal["exited", "time_limit", "output_limit", "shutdown", "not_started", "simulated"] = Field(
        default="exited", description="How the call ended: the program exited by itself; HybridSec stopped it at its "
                                      "time limit, or for printing more than the output limit, or because the server "
                                      "shut down; it could not be started; or it was simulated (never started).")
    duration_seconds: float = 0.0
    stdout: str = Field(default="", description="Standard output, cleaned and capped.")
    stderr: str = Field(default="", description="Standard error, cleaned and capped.")
    truncated: bool = Field(default=False, description="True when the output was longer than the limit and was cut, "
                                                       "or the tool was stopped for printing too much.")
    run_limit: bool = Field(default=False, description="True when the run's limit on custom-tool output (summed "
                                                       "over all calls) cut this call's output or left none of it.")


# --- Planner --------------------------------------------------------------------------------------

class PlanRequest(BaseModel):
    """What to plan: the tools to chain and the goal of the assessment."""

    tools: list[str] = Field(default_factory=lambda: ["nmap", "whatweb"], min_length=1, max_length=6,
                             description="Tools to chain (nmap, whatweb, nikto). Defaults to Nmap + WhatWeb.")
    objective: str = Field(..., min_length=10, max_length=2000,
                           description="What the assessment should achieve, in plain language.")
    target_hint: str | None = Field(
        default=None, max_length=255,
        description="Optional example target so the plan can be concrete. Surrounding spaces are removed; a "
                    "blank hint counts as none.",
    )

    @field_validator("target_hint", mode="before")
    @classmethod
    def _blank_hint_is_none(cls, value: Any) -> Any:
        """A hint of only spaces is no hint: the plan would otherwise read 'against    .' and the prompt would
        carry an empty example target."""
        if isinstance(value, str):
            return value.strip() or None
        return value


class PlanStep(BaseModel):
    """One step of a plan's workflow: one tool in one pipeline stage."""

    order: int = Field(description="Position of the step in the workflow, starting at 1.")
    tool: str = Field(description="Tool that performs the step.")
    stage: str = Field(description="One of: port_scan, web_fingerprint, web_vuln_scan, dns_lookup.")
    purpose: str = Field(description="Why the step is part of the workflow.")
    inputs: list[str] = Field(default_factory=list, description="What the step consumes.")
    outputs: list[str] = Field(default_factory=list, description="What the step hands to the next step.")
    command_template: str = Field(default="", description="Command HybridSec runs for the step with the tool's "
                                                          "default profile, with {target}, {top_ports}, {url} and "
                                                          "{timeout} placeholders. A run may choose another "
                                                          "profile, which its stage records.")


class SafetyControls(BaseModel):
    """The guard-rails a plan commits to."""

    authorization_required: bool = Field(default=True, description="Runs require explicit confirmation that the "
                                                                    "operator may test the target. Always true.")
    scope_restrictions: list[str] = Field(default_factory=list, description="Limits on what may be scanned.")
    rate_limits: list[str] = Field(default_factory=list, description="Limits on how hard and how long tools run.")
    data_handling: list[str] = Field(default_factory=list, description="How results are stored and protected.")


class Plan(BaseModel):
    """A structured hybrid-tool plan, produced by an AI provider or by the rules planner."""

    summary: str = Field(description="Two or three sentences describing the hybrid tool.")
    workflow: list[PlanStep] = Field(description="Ordered steps, one per tool.")
    inputs: list[str] = Field(description="What the operator supplies to a run.")
    outputs: list[str] = Field(description="What a run produces.")
    safety_controls: SafetyControls = Field(description="Authorization, scope, rate and data-handling controls.")
    limitations: list[str] = Field(default_factory=list, description="Known blind spots of the approach.")


class PlanResponse(BaseModel):
    """One saved plan revision. Refining a plan creates a new revision linked to its parent."""

    id: str = Field(description="Plan identifier. Pass it as plan_id to execute this plan.")
    status: Literal["planned"] = Field(default="planned", description="Always \"planned\".")
    provider: str = Field(description="Planner that produced the plan: anthropic, openai or rules.")
    model: str | None = Field(default=None, description="Model that actually answered; null for the rules planner.")
    note: str | None = Field(default=None, description="Set when the planner fell back to the rules engine or "
                                                          "kept the previous revision (it then explains why), or, for "
                                                          "a new plan, when it removed a tool the model added that was "
                                                          "not selected (a refined revision names such a tool in its "
                                                          "limitations instead).")
    created_at: datetime = Field(description="When the revision was created (UTC).")
    request: PlanRequest = Field(description="The request this revision answers. Its tools mirror the workflow.")
    plan: Plan = Field(description="The plan itself.")
    tools_available: dict[str, bool] = Field(description="Which tools were installed when the plan was made.")
    parent_id: str | None = Field(default=None, description="Plan this revision was refined from.")
    revision: int = Field(default=1, ge=1, description="1 for a new plan, one more for each refinement.")
    feedback: str | None = Field(default=None, description="Operator feedback that produced this revision.")


class RefineRequest(BaseModel):
    """Operator feedback for creating the next revision of a plan."""

    feedback: str = Field(..., min_length=3, max_length=2000,
                          description="What should change in the plan, in plain language.")


# --- Execution ------------------------------------------------------------------------------------

class ExecuteRequest(BaseModel):
    """What to scan, with which tools, and within which limits."""

    target: str = Field(
        ..., min_length=1, max_length=255,
        description="IPv4/IPv6 address, hostname, or CIDR (/24 or smaller).",
    )
    authorized: bool = Field(..., description="You confirm you own this target or have written permission.")
    timeout_seconds: int | None = Field(default=None, ge=10, le=86400,
                                           description="Time budget for the whole run; defaults to the server setting.")
    top_ports: int = Field(default=100, ge=1, le=65535,
                           description="How many of the most common ports Nmap probes (capped by the server maximum).")
    plan_id: str | None = Field(default=None, description="Execute the workflow from a saved plan.")
    tools: list[str] | None = Field(
        default=None,
        description="Override: tools to run, put into pipeline order automatically. Built-in tools run first in "
                    "stage order, then registered custom tools by name; at least one built-in tool is required. With "
                    "plan_id, may only leave tools out, so a custom tool cannot be added to a plan run. Custom tools "
                    "can only be run from the machine running HybridSec.",
    )
    simulate: bool = Field(default=False, description="Produce realistic sample output without touching the network.")
    label: str | None = Field(default=None, max_length=120, description="Optional name shown in the run history.")
    profiles: dict[str, str] | None = Field(
        default=None,
        description="Profile to use per tool, as {\"nmap\": \"quick\"}; the keys come from GET /api/tools. A tool "
                    "that is not named uses its default profile. Every tool named must be part of the run. Custom "
                    "tools have no profiles.",
    )


class PortFinding(BaseModel):
    """One open port found by Nmap."""

    host: str = Field(description="Address, or \"hostname (address)\" when Nmap resolved a name.")
    port: int
    protocol: str = "tcp"
    state: str = Field(default="open", description="Always \"open\": closed and filtered ports are not reported.")
    service: str = Field(default="", description="Service name. TLS-wrapped services are prefixed with \"ssl/\".")
    product: str = Field(default="", description="Software detected behind the port.")
    version: str = Field(default="", description="Software version taken from the service banner.")
    extra: str = Field(default="", description="Extra detail reported by Nmap, such as the operating system.")
    is_web: bool = Field(default=False, description="True when the web stages should probe this port.")


class WebFinding(BaseModel):
    """What WhatWeb learned about one web service."""

    url: str = Field(description="URL that was probed.")
    host: str
    port: int
    status_code: int | None = Field(default=None, description="HTTP status of the last response.")
    title: str | None = Field(default=None, description="HTML page title.")
    technologies: list[dict[str, Any]] = Field(default_factory=list,
                                               description="Detected technologies: a name, plus a version and/or "
                                                           "a descriptive string when WhatWeb found one.")
    reachable: bool = Field(default=True, description="False when the probe got no HTTP response at all.")
    final_url: str | None = Field(default=None, description="Where the probe ended after same-site redirects.")


class VulnFinding(BaseModel):
    """One web vulnerability finding reported by Nikto."""

    url: str = Field(description="URL the finding applies to.")
    severity: str = Field(default="info", description="critical, high, medium, low or info. Estimated from "
                                                      "keywords, because Nikto does not grade its findings.")
    description: str = Field(description="The finding as Nikto describes it.")
    reference: str = Field(default="", description="Reference such as an advisory id or a URL, when available.")

    @field_validator("severity", "reference", mode="before")
    @classmethod
    def _null_is_default(cls, value: Any, info: Any) -> Any:
        """A stored finding with a null severity or reference (HybridSec never writes one, but a hand-edited or
        foreign document might) loads with the default, so one damaged finding cannot make the run, its
        reports and the comparison unreadable."""
        if value is None:
            return "info" if info.field_name == "severity" else ""
        return value


class StageResult(BaseModel):
    """Progress and outcome of one pipeline stage within a run."""

    stage: str = Field(description="Pipeline stage name.")
    tool: str = Field(description="Tool that runs the stage.")
    status: Literal["pending", "running", "completed", "failed", "skipped", "simulated"] = Field(
        default="pending",
        description="skipped means there was no input (for example no web services); simulated means the "
                    "stage produced synthetic data.",
    )
    command: str = Field(default="", description="Command line(s) executed, one per line. Temporary file paths "
                                                 "are shown as <file>.")
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    exit_code: int | None = Field(default=None, description="The tool's exit code: Nmap's, or that of a custom tool "
                                                               "that runs once on the target. Null when the program "
                                                               "did not exit by itself: it was stopped at its time "
                                                               "limit, or a custom tool was stopped for printing too "
                                                               "much or by the server shutdown, or could not be "
                                                               "started. An Nmap that could not be started or that the "
                                                               "server shutdown stopped is recorded as 127. Always "
                                                               "null for the per-URL stages.")
    error: str | None = Field(default=None, description="Why the stage failed or was skipped. For a completed "
                                                           "stage: notes about partial results.")
    partial: bool = Field(default=False, description="True when the stage completed without examining everything "
                                                     "it was given: it ran out of time (Nmap stopped at the stage "
                                                     "limit, a host timeout, URLs skipped or probes stopped at their "
                                                     "limit) or a tool produced nothing for a URL. `error` then "
                                                     "says what is missing.")
    raw_output_chars: int = Field(default=0, description="Size of the tool's standard output, for diagnostics. A "
                                                         "custom tool's text itself is in Run.custom_outputs.")


class RunSummary(BaseModel):
    """Headline numbers of a run, as shown on the dashboard and in reports."""

    hosts_up: int = Field(default=0, description="Hosts known to be up: those Nmap reported (with at least one open "
                                                 "port, plus any that hit the host timeout; --open leaves hosts "
                                                 "without open ports out of the report) and, in a workflow without "
                                                 "a port scan, those that answered a web probe or that Nikto "
                                                 "examined. "
                                                 "1 for a simulated run.")
    open_ports: int = Field(default=0, description="Open ports found.")
    web_services: int = Field(default=0, description="Web services that answered HTTP.")
    technologies: int = Field(default=0, description="Technologies detected on those web services.")
    vulnerabilities: int = Field(default=0, description="Findings reported by Nikto.")
    risk_score: int = Field(
        default=0, ge=0, le=100,
        description="Heuristic 0-100 exposure score built from open ports, web services, disclosed versions "
                    "and findings.",
    )
    highlights: list[str] = Field(default_factory=list, description="Up to eight short notable observations.")
    partial: bool = Field(default=False, description="True when the run completed with gaps: a stage completed with "
                                                     "partial results or a later stage failed (see the stages' "
                                                     "notes). A port, technology or finding that is absent is then "
                                                     "not evidence of its absence. False for a failed run, whose "
                                                     "status already says so. Custom tool stages do not count: their "
                                                     "output is not part of the findings.")

    @model_validator(mode="before")
    @classmethod
    def _nulls_are_defaults(cls, data: Any) -> Any:
        """A stored summary with a null field (HybridSec never writes one, but a hand-edited or foreign document
        might) loads with that field's default, and a risk score outside 0-100 is clamped, so one damaged
        document cannot break the whole history."""
        if isinstance(data, dict):
            data = {key: value for key, value in data.items() if value is not None}
            score = data.get("risk_score")
            if isinstance(score, float) and not math.isfinite(score):
                data.pop("risk_score")  # infinity or NaN (1e999 in JSON) is no score at all
            elif isinstance(score, int | float) and not isinstance(score, bool):
                data["risk_score"] = max(0, min(100, int(score)))
        return data


class Run(BaseModel):
    """One execution of the hybrid pipeline: live progress while it runs, then the complete result."""

    id: str
    label: str | None = Field(default=None, description="Optional name from the request.")
    target: str = Field(description="Normalised target that was scanned.")
    status: Literal["queued", "running", "completed", "failed"] = Field(
        default="queued",
        description="completed means the pipeline finished (a later stage may still have failed, see error); "
                    "failed means the first stage failed or the pipeline crashed.",
    )
    mode: Literal["live", "simulated"] = Field(default="live", description="simulated runs contain synthetic data.")
    plan_id: str | None = Field(default=None, description="Plan whose workflow this run executed.")
    tools: list[str] = Field(description="Tools in pipeline order.")
    profiles: dict[str, str] = Field(default_factory=dict,
                                     description="Profile key used for each tool (see GET /api/tools). Empty for "
                                                 "runs recorded before profiles existed, which used the defaults.")
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    stages: list[StageResult] = Field(default_factory=list, description="One entry per tool, in execution order.")
    ports: list[PortFinding] = Field(default_factory=list, description="Open ports (port_scan stage).")
    web: list[WebFinding] = Field(default_factory=list, description="Fingerprinted web services "
                                                                    "(web_fingerprint stage).")
    vulns: list[VulnFinding] = Field(default_factory=list, description="Findings (web_vuln_scan stage).")
    custom_tools: dict[str, CustomTool] = Field(default_factory=dict,
                                                description="Copy of each custom tool the run uses, as it was "
                                                            "registered when the run started.")
    custom_outputs: list[CustomToolOutput] = Field(default_factory=list,
                                                   description="What each custom tool call printed, in execution "
                                                               "order. Not parsed into findings or scored.")
    summary: RunSummary = Field(default_factory=RunSummary, description="Headline numbers, risk score and highlights.")
    log: list[str] = Field(default_factory=list, description="Timestamped execution log.")
    error: str | None = Field(default=None, description="Why the run failed, or which later stages failed.")

    @field_validator("custom_tools", "custom_outputs", mode="before")
    @classmethod
    def _custom_or_empty(cls, value: Any, info: Any) -> Any:
        """Runs stored before custom tools existed have neither field; a null one (from a hand-edited or foreign
        document) loads as empty too."""
        if value is None:
            return {} if info.field_name == "custom_tools" else []
        return value

    @field_validator("profiles", mode="before")
    @classmethod
    def _profiles_or_empty(cls, value: Any) -> Any:
        """A stored document with "profiles": null, or a null profile key (HybridSec never writes either, but
        a hand-edited or foreign document might) means no record, like a document without the field."""
        return _profiles_or_empty(value)

    @field_validator("summary", mode="before")
    @classmethod
    def _summary_or_default(cls, value: Any) -> Any:
        """A stored document whose "summary" is null or not an object loads with the default (empty) summary,
        like a document without the field, so one foreign document cannot break the whole history."""
        return _summary_or_default(value)

    @field_validator("tools", mode="before")
    @classmethod
    def _tools_or_empty(cls, value: Any) -> Any:
        return [] if value is None else value

    @field_validator("mode", mode="before")
    @classmethod
    def _mode_or_live(cls, value: Any) -> Any:
        return "live" if value is None else value


class RunListItem(BaseModel):
    """A run without its findings and log, for the history list."""

    id: str
    label: str | None
    target: str
    status: str
    mode: str
    tools: list[str]
    profiles: dict[str, str] = Field(default_factory=dict, description="Profile key used for each tool.")
    created_at: datetime
    duration_seconds: float | None
    summary: RunSummary

    @field_validator("profiles", mode="before")
    @classmethod
    def _profiles_or_empty(cls, value: Any) -> Any:
        return _profiles_or_empty(value)

    @field_validator("summary", mode="before")
    @classmethod
    def _summary_or_default(cls, value: Any) -> Any:
        return _summary_or_default(value)

    @field_validator("tools", mode="before")
    @classmethod
    def _tools_or_empty(cls, value: Any) -> Any:
        return [] if value is None else value

    @field_validator("mode", mode="before")
    @classmethod
    def _mode_or_live(cls, value: Any) -> Any:
        return "live" if value is None else value


def _profiles_or_empty(value: Any) -> Any:
    """Stored profiles without the null entries, or {} for a null field."""
    if isinstance(value, dict):
        return {tool: key for tool, key in value.items() if key is not None}
    return value or {}


def _summary_or_default(value: Any) -> Any:
    """A stored summary, or the default (empty) one when the stored value is null or not an object."""
    return value if isinstance(value, dict | RunSummary) else {}


# --- Comparison -----------------------------------------------------------------------------------

class CompareResponse(BaseModel):
    """Differences between two runs. "added" means present only in `other`, "removed" only in `base`."""

    base: RunListItem
    other: RunListItem
    ports_added: list[PortFinding]
    ports_removed: list[PortFinding]
    ports_changed: list[dict[str, Any]] = Field(description="Ports open in both runs whose service, product or "
                                                            "version changed, with before and after values.")
    tech_added: list[dict[str, Any]]
    tech_removed: list[dict[str, Any]]
    vulns_added: list[VulnFinding]
    vulns_removed: list[VulnFinding]
    risk_delta: int | None = Field(default=None, description="Risk score of other minus risk score of base; null "
                                                                "unless both runs completed (only completed runs "
                                                                "are scored).")
    note: str | None = Field(default=None, description="Warning when either run failed, is still executing or has "
                                                          "partial results (what is missing from such a run is not "
                                                          "evidence of a change), when a tool ran in only one of "
                                                          "the runs (its results then appear as added or removed), "
                                                          "when the runs used different profiles for a tool, or "
                                                          "when either run used custom tools, whose output is not "
                                                          "compared.")


# --- System ---------------------------------------------------------------------------------------

class Limits(BaseModel):
    """Scanning limits currently in force (configured in .env or on the Settings page)."""

    max_timeout_seconds: int = Field(description="Largest time budget a run may request.")
    default_timeout_seconds: int = Field(description="Time budget used when a run does not ask for one.")
    max_top_ports: int = Field(description="Upper bound for top_ports.")
    max_concurrent_runs: int = Field(description="Runs that may execute at the same time.")


class RunCounts(BaseModel):
    """How many runs are stored, for the Overview totals (the run list the dashboard loads is capped)."""

    total: int = 0
    completed: int = 0
    failed: int = 0
    active: int = Field(default=0, description="Runs queued or executing.")


class HealthResponse(BaseModel):
    """Server status and configuration summary, used by the dashboard's Overview page."""

    status: str = Field(description="Always \"ok\" when the server answers.")
    app: str
    version: str
    ai_provider: str = Field(description="Planner backend that will be used: anthropic, openai or rules.")
    ai_model: str | None = Field(description="Model the planner will use; null for the rules planner.")
    simulation_allowed: bool = Field(description="Whether runs may use simulation mode.")
    allowed_targets: list[str] = Field(description="Target allow-list. Empty means any target the operator "
                                                   "confirms as authorized.")
    tools: dict[str, bool] = Field(description="Which tools are installed.")
    limits: Limits
    runs: RunCounts = Field(default_factory=RunCounts, description="How many runs are stored, by outcome.")
