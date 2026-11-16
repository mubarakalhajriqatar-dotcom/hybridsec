"""System endpoints: server health with a configuration summary, the tool catalogue with install status, and the
custom tools the operator registers on the dashboard's Custom tools page (only from the machine running HybridSec;
see tools/custom.py for the rules)."""
from __future__ import annotations

import urllib.parse
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from starlette.convertors import Convertor, register_url_convertor

from .. import storage
from ..config import settings
from ..schemas import CustomToolCreate, CustomToolInfo, CustomToolList, HealthResponse, Limits, RunCounts, ToolInfo
from ..tools import custom
from ..tools.registry import TOOLS, availability, list_tools
from .settings_api import require_local

router = APIRouter(prefix="/api", tags=["System"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Server status, the planner that will be used, which tools are installed, and the scanning limits.

    The dashboard's Overview page is built from this response, its run totals included. It never includes
    secrets.
    """
    counts = storage.count_runs()
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        version=settings.version,
        ai_provider=settings.resolved_ai_provider(),
        ai_model=settings.ai_model(),
        simulation_allowed=settings.allow_simulation,
        allowed_targets=settings.allowed_targets,
        tools=availability(),
        limits=Limits(
            max_timeout_seconds=settings.max_timeout_seconds,
            default_timeout_seconds=settings.default_timeout_seconds,
            max_top_ports=settings.max_top_ports,
            max_concurrent_runs=settings.max_concurrent_runs,
        ),
        runs=RunCounts(total=sum(counts.values()), completed=counts.get("completed", 0),
                       failed=counts.get("failed", 0), active=counts.get("queued", 0) + counts.get("running", 0)),
    )


@router.get("/tools", response_model=list[ToolInfo], summary="Supported tools and whether they are installed")
def tools() -> list[ToolInfo]:
    """Every supported tool with its install status, version and install hint."""
    return list_tools()


# --- Custom tools ---------------------------------------------------------------------------------

@router.get("/tools/custom", response_model=CustomToolList, dependencies=[Depends(require_local)],
            summary="Registered custom tools (machine running HybridSec only)")
def custom_tools() -> CustomToolList:
    """The registered custom tools, whether each can run on this machine (and if not, why), the programs that may
    be registered (as written in .env, without those that are always refused), and the names of stored tools whose
    definition can no longer be read (they can still be deleted). Starts no program."""
    allowed = custom.allowed_programs(settings.custom_programs)
    tools, unreadable = storage.custom_tool_rows()
    return CustomToolList(
        allowed_programs=custom.allowed_program_names(settings.custom_programs),
        tools=[custom.tool_info(tool, allowed, settings.allow_simulation) for tool in tools],
        unreadable=unreadable,
    )


@router.post("/tools/custom", response_model=CustomToolInfo, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_local)], summary="Register a custom tool (machine running HybridSec only)")
def add_custom_tool(body: CustomToolCreate) -> CustomToolInfo:
    """Register an extra command-line tool. It then appears on New Run and runs after the built-in tools; its
    output is kept as text and never scored. To change a tool, delete it and register it again."""
    allowed = custom.allowed_programs(settings.custom_programs)
    try:
        tool = custom.validate_definition(body, allowed, datetime.now(timezone.utc))
    except custom.CustomToolError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    if tool.timeout_seconds > settings.max_timeout_seconds:
        raise HTTPException(status_code=400,
                            detail=f"timeout_seconds may not exceed {settings.max_timeout_seconds}. "
                                   "Ask for a shorter limit or raise the maximum on the Settings page.")
    outcome = storage.add_custom_tool(tool, custom.MAX_CUSTOM_TOOLS)
    if outcome == "full":
        raise HTTPException(status_code=400, detail=f"At most {custom.MAX_CUSTOM_TOOLS} custom tools can be "
                                                    "registered. Delete one first.")
    if outcome == "exists":
        raise HTTPException(status_code=409, detail=f"A custom tool named {tool.name} already exists. Delete it first "
                                                    "to change it.")
    return custom.tool_info(tool, allowed, settings.allow_simulation)


class _AnyText(Convertor[str]):
    """Starlette's path convertor with line breaks too: the "." of its regex matches no line break, and a stored row
    name (one in unreadable comes from a hand-edited or foreign row) may hold one."""

    regex = r"[\s\S]*"

    def convert(self, value: str) -> str:
        return value

    def to_string(self, value: str) -> str:
        return value


register_url_convertor("anytext", _AnyText())


# {name:anytext}: a stored row name may hold / ? # % or a line break, which the dashboard percent-encodes; the plain
# {name} form would not match a decoded /, nor {name:path} a line break.
@router.delete("/tools/custom/{name:anytext}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response,
               dependencies=[Depends(require_local)], summary="Delete a custom tool (machine running HybridSec only)")
def delete_custom_tool(name: str, request: Request) -> Response:
    """Remove a custom tool, by the name GET /api/tools/custom lists it under (in tools or in unreadable; the name
    is also matched in lower case without surrounding spaces), percent-encoded in the path, so a name with / ? # or %
    can be deleted too. Runs that already used it keep their own copy of it and their output."""
    name = _name_as_sent(request, name)
    key = name.strip().lower()
    # The name as given first, then its stored form: a hand-edited row (HDR, or one named after a built-in tool) is
    # listed under its own name and must stay deletable by it.
    if storage.delete_custom_tool(name) or (key != name and storage.delete_custom_tool(key)):
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if key in TOOLS:
        raise HTTPException(status_code=400, detail=f"{key} is a built-in tool and cannot be deleted.")
    raise HTTPException(status_code=404, detail="Custom tool not found.")


def _name_as_sent(request: Request, decoded: str) -> str:
    """The {name} path segment decoded exactly once, from the request's raw path. The decoded path a server passes
    on is used when there is no raw path; Starlette's test client decodes that one twice, so a name such as c%2Fd
    (sent as c%252Fd) would arrive as c/d."""
    raw = request.scope.get("raw_path")
    if isinstance(raw, bytes):
        _head, found, tail = raw.partition(b"/tools/custom/")
        if found:
            try:
                return urllib.parse.unquote(tail.decode("ascii"))
            except UnicodeDecodeError:  # a raw path that is not plain ASCII: keep the server's reading
                pass
    return decoded
