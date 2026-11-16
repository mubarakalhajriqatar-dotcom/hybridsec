"""Run execution endpoint: validate a request, decide which tools to run, and queue the run.

Every check that can reject a run happens here, before anything is started, and in a fixed order: the
target (authorization, syntax, scope), the time budget, simulation mode, the tool selection, the custom tools
(at least one built-in tool, a local peer, and a definition that still passes the rules), the tool profiles,
the Nmap requirement for a network range, and finally whether the first tool is installed. The run itself is
executed by hybrid.manager in the background.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from .. import storage
from ..config import settings
from ..hybrid import RunLimitExceeded, manager
from ..schemas import CustomTool, ExecuteRequest, Run
from ..security import TargetError, is_network_range, validate_execution_target
from ..tools import custom as custom_rules
from ..tools.registry import (
    DEFAULT_TOOLS,
    TOOLS,
    availability,
    default_profile,
    describe_unknown_tools,
    find_profile,
    known_tool,
    order_tools,
    unknown_tools,
)
from .settings_api import peer_is_local

router = APIRouter(prefix="/api/hybridizations", tags=["Hybrid execution"])


@router.post("/execute", response_model=Run, status_code=status.HTTP_202_ACCEPTED,
             summary="Start a hybrid assessment run")
def execute(request: ExecuteRequest, local: bool = Depends(peer_is_local)) -> Run:
    """Validate the request and start the run in the background. Answers 202 with the queued run;
    poll GET /api/runs/{id} to follow its progress."""
    target = _validated_target(request)
    timeout_seconds = _time_budget(request)
    if request.simulate and not settings.allow_simulation:
        raise HTTPException(status_code=400, detail="Simulation mode is disabled on this server. "
                                                    "Enable it on the Settings page or run without simulate.")
    # The registered custom tools are only read when the request names a tool that is not built in.
    named = [*(request.tools or []), *(request.profiles or {})]
    custom = {tool.name: tool for tool in storage.list_custom_tools()} if not all(map(known_tool, named)) else {}
    plan_id, tools = _select_tools(request, custom, local)
    _check_custom_tools(tools, custom, local)
    profiles = _select_profiles(request, tools, custom)
    if is_network_range(target) and "nmap" not in tools:
        raise HTTPException(status_code=400,
                            detail="A network range needs the Nmap port-scan stage to discover hosts. "
                                   "Add nmap or give a single host.")
    if not request.simulate:
        _require_first_tool_installed(tools)
    try:
        return manager.create(request, target, tools, plan_id, timeout_seconds, profiles,
                              {t: custom[t] for t in tools if t in custom})
    except RunLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


def _validated_target(request: ExecuteRequest) -> str:
    try:
        return validate_execution_target(request.target, request.authorized)
    except TargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _time_budget(request: ExecuteRequest) -> int:
    """The run's time budget in seconds: the requested one, or the server default."""
    timeout_seconds = request.timeout_seconds or settings.default_timeout_seconds
    if timeout_seconds > settings.max_timeout_seconds:
        raise HTTPException(status_code=400,
                            detail=f"timeout_seconds may not exceed {settings.max_timeout_seconds}. "
                                   "Ask for a shorter budget or raise the maximum on the Settings page.")
    return timeout_seconds


def _select_tools(request: ExecuteRequest, custom: dict[str, CustomTool],
                  local: bool) -> tuple[str | None, list[str]]:
    """Decide which tools the run executes, and which saved plan it follows (if any).

    A run started from a plan executes that plan's workflow. The operator may leave a planned tool out but
    never add one the approved plan does not contain; plans never contain custom tools, so a custom tool cannot
    be added to a plan run. With neither a plan nor a tool list, the run uses DEFAULT_TOOLS. An unknown name is
    answered with the tools the client may choose from: the registered custom tools a run can use are named only to
    a client on the machine running HybridSec, because only it may list them (GET /api/tools/custom).
    """
    if request.tools is not None:
        unknown = unknown_tools(request.tools, custom)
        if unknown:
            supported = [*TOOLS, *_usable_custom_tools(custom)] if local else list(TOOLS)
            raise HTTPException(status_code=400,
                                detail=f"Unknown tool(s): {describe_unknown_tools(unknown)}. "
                                       f"Supported: {', '.join(supported)}.")

    if not request.plan_id:
        tools = order_tools(request.tools, custom) if request.tools else []
        return None, tools or list(DEFAULT_TOOLS)

    plan = storage.get_plan(request.plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found.")
    plan_tools = order_tools([step.tool for step in plan.plan.workflow])
    if not request.tools:
        return plan.id, plan_tools or list(DEFAULT_TOOLS)
    # Every name was checked above, so `requested` holds at least one tool.
    requested = order_tools(request.tools, custom)
    extra = [t for t in requested if t not in plan_tools]
    if extra:
        raise HTTPException(status_code=400,
                            detail=f"Tool(s) {', '.join(extra)} are not part of plan {plan.id}'s workflow "
                                   f"({', '.join(plan_tools)}). Clear the plan or adjust the selection.")
    return plan.id, requested


def _usable_custom_tools(custom: dict[str, CustomTool]) -> list[str]:
    """The registered custom tools a run can use, by name: those whose definition still passes the rules. One that
    is refused (the Custom tools page says why), or whose stored name is not written the way registration writes
    names (HDR, or a built-in tool's name), would only be refused in turn, so the unknown-tool error leaves it out."""
    allowed = custom_rules.allowed_programs(settings.custom_programs)
    return sorted(name for name, tool in custom.items() if custom_rules.definition_problem(tool, allowed) is None)


def _check_custom_tools(tools: list[str], custom: dict[str, CustomTool], local: bool) -> None:
    """Refuse custom tools the run may not use. A run needs at least one built-in tool, because custom output is
    not scored and the first stage feeds every later one; custom tools only run for a request from the machine
    running HybridSec, like their registration; and a definition that no longer passes the rules (the allow-list
    was shortened, the row was edited by hand) is refused instead of run. A stored tool named after a built-in tool
    (a hand-edited row) cannot be registered again under that name, so the operator is told to delete it."""
    chosen = [tool for tool in tools if tool in custom]
    if not chosen:
        return
    if not any(tool in TOOLS for tool in tools):
        raise HTTPException(status_code=400, detail="Choose at least one of nmap, whatweb or nikto: custom tools run "
                                                    "after them and are not scored.")
    if not local:
        raise HTTPException(status_code=403, detail="Custom tools can only be run from the machine running HybridSec. "
                                                    "Open the dashboard on that machine, or leave them out.")
    allowed = custom_rules.allowed_programs(settings.custom_programs)
    for name in chosen:
        problem = custom_rules.definition_problem(custom[name], allowed)
        if problem and name in TOOLS:
            raise HTTPException(status_code=400, detail=f"A stored custom tool is named {name}, like the built-in "
                                                        "tool, so the run cannot tell them apart. Delete that custom "
                                                        "tool on the Custom tools page, then start the run again.")
        if problem:
            raise HTTPException(status_code=400, detail=f"{name} no longer passes the registration rules: {problem} "
                                                        "Delete it and register it again.")


def _select_profiles(request: ExecuteRequest, tools: list[str], custom: dict[str, CustomTool]) -> dict[str, str]:
    """The profile each built-in tool of the run uses: the requested one, or the tool's default.

    A profile may only be named for a tool that is part of the run, and must be one the tool offers (GET
    /api/tools lists them), so a typo is reported instead of silently running the default. A plan does not
    restrict profiles: like top_ports and the time budget, they decide how a planned tool runs, not which
    tools run. Custom tools have no profiles.
    """
    chosen: dict[str, str] = {}
    for raw_tool, raw_key in (request.profiles or {}).items():
        if raw_tool.strip().lower() in custom:
            raise HTTPException(status_code=400,
                                detail=f"{raw_tool.strip().lower()} is a custom tool and has no profiles.")
        if not known_tool(raw_tool):
            raise HTTPException(status_code=400,
                                detail=f"Unknown tool in profiles: {raw_tool[:80]}. Supported: {', '.join(TOOLS)}.")
        tool = raw_tool.strip().lower()
        if tool not in tools:
            raise HTTPException(status_code=400,
                                detail=f"A profile was given for {tool}, which is not part of this run "
                                       f"({', '.join(tools)}).")
        profile = find_profile(tool, raw_key)
        if profile is None:
            offered = ", ".join(p.key for p in TOOLS[tool].profiles)
            raise HTTPException(status_code=400,
                                detail=f"Unknown {tool} profile: {raw_key[:80]}. Choose one of: {offered}.")
        if chosen.get(tool, profile.key) != profile.key:  # "nmap" and " NMAP " naming different profiles
            raise HTTPException(status_code=400,
                                detail=f"profiles names {tool} more than once with different values.")
        chosen[tool] = profile.key
    return {tool: chosen.get(tool, default_profile(tool).key) for tool in tools if tool in TOOLS}


def _require_first_tool_installed(tools: list[str]) -> None:
    """Refuse a live run whose first tool is missing, since that stage feeds every later one.

    A missing later tool is allowed: its stage fails on its own and the run still completes with the
    results of the earlier stages.
    """
    first = tools[0]
    if not availability().get(first):
        fix = ("Install it, or set simulate=true to demo the pipeline without the tools."
               if settings.allow_simulation else "Install it and try again.")
        raise HTTPException(status_code=400, detail=f"{first} is not installed, so the first stage cannot run. {fix}")
