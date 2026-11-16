"""HybridSec web application: the FastAPI app, its request guards, the API routers and the dashboard.

Run with:  run.ps1 or run.sh, or  .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
Docs at    http://127.0.0.1:8000/docs   Dashboard at http://127.0.0.1:8000/

Every request first passes guard_requests(), which reloads the settings and rejects requests that could
come from DNS rebinding or a cross-site page. The routers in app/routers/ then handle /api/..., and the
static dashboard is served from the dashboard/ folder.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
from contextlib import asynccontextmanager, suppress
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.utils import is_body_allowed_for_status_code
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import storage
from .config import host_without_port, settings
from .hybrid import manager as run_manager
from .hybrid import summarize as summarize_run
from .routers import ai, hybrid, runs, settings_api, tools
from .schemas import ExecuteRequest, PlanRequest, PlanResponse, Run
from .tools.runner import accept_new_processes, install_exit_cleanup, terminate_all

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("hybridsec")

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Startup: create the tables and fail runs that a previous process left "running".
    Shutdown: kill scanner processes that would otherwise outlive the server."""
    storage.init_db()
    accept_new_processes()  # re-arm the scanner runner after a previous lifespan's shutdown
    install_exit_cleanup()  # scanners are killed even when an exit skips the shutdown below
    stale = storage.fail_stale_runs(summarize=summarize_run)
    if stale:
        log.warning("Marked %d interrupted run(s) as failed after restart.", stale)
    yield
    killed = terminate_all()
    if killed:
        log.warning("Terminated %d scanner process(es) on shutdown.", killed)
    # Each executing run now ends as interrupted by the shutdown; give it a moment to save that before the
    # process exits, or the next start would only find it "running" and blame a restart.
    if not await asyncio.to_thread(run_manager.wait_until_idle, 5.0):
        log.warning("A run was still executing at shutdown; the next start marks it as failed.")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "AI-planned hybrid cybersecurity tooling: chain Nmap, WhatWeb and Nikto into one correlated "
        "assessment with a built-in dashboard. For authorized testing only."
    ),
    lifespan=lifespan,
)


# --- Request guards -------------------------------------------------------------------------------

def _hostname(value: str) -> str:
    """'host:port', '[::1]:8000' or a full URL -> the lower-case host name without the port."""
    value = (value or "").strip().lower()
    if "://" in value:
        # A malformed URL such as http://[::1 names no host this server answers to: it is then compared as
        # it is, and rejected.
        with suppress(ValueError):
            value = urlsplit(value).netloc
    return host_without_port(value)


def _reject_unknown_host(request: Request) -> JSONResponse | None:
    """400 when the Host header names a server other than this one: the signature of DNS rebinding.

    In a rebinding attack a malicious site makes its own domain name resolve to 127.0.0.1, so the victim's
    browser talks to HybridSec while the Host header still carries the attacker's domain. A request without
    a Host header cannot come from a browser and passes. Under an unknown name /api/health still answers for
    uptime checks, but only with {"status": "ok"}: the full summary (target allow-list, planner, tools and
    limits) goes only to trusted names, because a rebinding page could read it.
    """
    host = _hostname(request.headers.get("host", ""))
    if host and host not in settings.allowed_hosts:
        if request.url.path == "/api/health" and request.method == "GET":
            return JSONResponse({"status": "ok"})  # liveness only, and only for the method the route serves
        return JSONResponse(status_code=400, content={"detail": f"Invalid Host header '{host}'. Add it to "
                                                                "HYBRIDSEC_ALLOWED_HOSTS if this is intended."})
    return None


def _reject_cross_site(request: Request) -> JSONResponse | None:
    """403 when a state-changing request was sent by a browser on another site.

    Browsers label such requests with an Origin header naming the other site, or with Sec-Fetch-Site:
    cross-site. Non-browser clients (curl, scripts) send neither header and are unaffected. An Origin of
    "null" (file:// pages, sandboxed frames) carries no host to compare, so only the Sec-Fetch-Site check
    applies to it.
    """
    if request.method not in STATE_CHANGING_METHODS:
        return None
    origin = request.headers.get("origin")
    if origin and origin != "null":
        # Same origin means the same host AND port as the request itself: another local application on a
        # different port is a different origin, even though its host name is on the allow-list.
        try:
            origin_netloc = urlsplit(origin.strip().lower()).netloc
        except ValueError:  # a malformed Origin (http://[::1) names no site this server belongs to
            origin_netloc = None
        request_host = request.headers.get("host", "").strip().lower()
        if origin_netloc != request_host or _hostname(origin) not in settings.allowed_hosts:
            return JSONResponse(status_code=403, content={"detail": "Cross-origin request rejected. "
                                                                    "Use the dashboard served by this server."})
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return JSONResponse(status_code=403, content={"detail": "Cross-site request rejected. "
                                                                "Use the dashboard served by this server."})
    return None


def _forbid_framing(response: Response) -> Response:
    """No other site may show HybridSec in a frame: a hidden frame could trick the operator into clicking
    Delete or Clear key (clickjacking), and requests made from inside the frame are same-origin. Applied to
    every response, the guards' rejections and the liveness-only health answer included."""
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    return response


@app.middleware("http")
async def guard_requests(request: Request, call_next):
    """Runs before every request: refresh the settings, then apply the Host and cross-site guards."""
    settings.reload()  # .env edits (allow-lists, keys, limits) apply from this request on
    rejection = _reject_unknown_host(request) or _reject_cross_site(request)
    if rejection is not None:
        return _forbid_framing(rejection)
    response = _forbid_framing(await call_next(request))
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        # Browsers must re-check the dashboard files on every load (cheap 304s) so an upgraded
        # HybridSec never runs with a stale cached app.js or index.html.
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    """A crash inside a request answers a plain 500 that still carries the anti-framing headers: Starlette
    builds its own 500 page outside guard_requests(). The server logs the traceback as before, because the
    exception is re-raised after this answer is sent."""
    return _forbid_framing(JSONResponse(status_code=500, content={"detail": "Internal Server Error"}))


class _AsciiJSONResponse(JSONResponse):
    """A JSON response written in ASCII: every other character becomes a \\u escape, so text that cannot be
    encoded as UTF-8 (a lone surrogate from an invalid \\ud800 escape in the request) still gives valid JSON."""

    def render(self, content: Any) -> bytes:
        return json.dumps(_finite(content), ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


def _finite(value: Any) -> Any:
    """`value` with every infinite or NaN float written as text, which JSON has no number for."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {key: _finite(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_finite(item) for item in value]
    return value


# The answer to a malformed body whose list of errors cannot be written at all.
_UNREADABLE_BODY = ("The request body does not have the expected shape. Check it against the API documentation "
                    "at /docs.")


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
    """The usual 422 with FastAPI's list of errors: where each problem is (loc), what it is (msg) and its type.

    FastAPI also echoes the rejected value in each error, and that echo once turned the answer into a 500: a value
    holding a lone surrogate or a NaN could not be written, and lists nested a thousand deep exceed Python's
    recursion limit when encoded. So the value is left out (see _plain_error), and should an error still not
    encode, the client gets a 422 with a fixed message instead."""
    try:
        errors = [_plain_error(error) for error in exc.errors()]
        return _AsciiJSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})
    except (RecursionError, ValueError, TypeError):
        return _AsciiJSONResponse(status_code=422, content={"detail": _UNREADABLE_BODY})


def _plain_error(error: Any) -> Any:
    """One validation error without the rejected value ("input"), and with only the plain values of the rule's
    parameters ("ctx", such as max_length or the JSON parser's reason); anything else in ctx is dropped."""
    if not isinstance(error, dict):
        return error
    plain = {key: value for key, value in error.items() if key not in ("input", "ctx")}
    ctx = error.get("ctx")
    if isinstance(ctx, dict):
        scalars = {key: value for key, value in ctx.items() if isinstance(value, (str, int, float, bool))}
        if scalars:
            plain["ctx"] = scalars
    return plain


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
    """FastAPI's usual answer to an HTTPException, written in ASCII: a detail may quote the request (an unknown
    tool name, a rejected allow-list entry), and a lone surrogate in it could not be encoded as UTF-8."""
    headers = getattr(exc, "headers", None)
    if not is_body_allowed_for_status_code(exc.status_code):
        return Response(status_code=exc.status_code, headers=headers)
    return _AsciiJSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=headers)


@app.exception_handler(storage.DocumentUnreadable)
async def unreadable_document(request: Request, exc: storage.DocumentUnreadable) -> JSONResponse:
    """A stored plan or run that no longer loads answers 422 with an explanation instead of a bare 500."""
    return JSONResponse(status_code=422, content={"detail": str(exc)})


# --- API routers ----------------------------------------------------------------------------------

app.include_router(tools.router)
app.include_router(ai.router)
app.include_router(hybrid.router)
app.include_router(runs.router)
app.include_router(settings_api.router)


# Legacy paths from the original project, kept so the earlier Swagger walkthrough still works.
@app.post("/ai/plan", response_model=PlanResponse, tags=["Legacy aliases"], include_in_schema=True)
def legacy_plan(request: PlanRequest) -> PlanResponse:
    """Same as POST /api/ai/plan."""
    return ai.plan(request)


@app.post("/hybridizations/execute", response_model=Run, status_code=202, tags=["Legacy aliases"])
def legacy_execute(request: ExecuteRequest, local: bool = Depends(settings_api.peer_is_local)) -> Run:
    """Same as POST /api/hybridizations/execute."""
    return hybrid.execute(request, local)


# --- Dashboard ------------------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(settings.dashboard_dir)), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(settings.dashboard_dir / "index.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_redirect() -> RedirectResponse:
    return RedirectResponse(url="/")


# A shield icon, served inline so the dashboard needs no image files.
_FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<path d="M16 2 4 7v8c0 7.5 5.1 13.2 12 15 6.9-1.8 12-7.5 12-15V7L16 2z" fill="#0b1220" stroke="#22d3ee" '
    'stroke-width="2"/>'
    '<path d="M10.5 16.5l3.5 3.5 7.5-8" fill="none" stroke="#22d3ee" stroke-width="2.5" stroke-linecap="round" '
    'stroke-linejoin="round"/>'
    "</svg>"
)


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(content=_FAVICON, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})
