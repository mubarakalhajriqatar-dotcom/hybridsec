"""SQLite persistence for plans, runs and custom tools.

Each plan or run is stored as one JSON document (its pydantic model dumped to JSON), with a few columns
copied out for sorting and filtering. The table layout therefore never has to change when the models gain
a field. Every call opens its own short-lived connection, and a process-wide lock serialises them,
because API requests and run worker threads all write here and SQLite allows one writer at a time.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timezone

from .config import settings
from .schemas import CustomTool, PlanResponse, Run, RunListItem, RunSummary

log = logging.getLogger("hybridsec.storage")

_lock = threading.RLock()
# How every run and plan id looks (uuid4 hex, cut); a row with another id cannot be addressed by the API.
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


class DocumentUnreadable(ValueError):
    """A stored plan or run that no longer loads: the document is damaged, was edited by hand, or was written
    by an incompatible version. main.py answers it with a 422 that says so instead of a bare 500."""

    def __init__(self, kind: str, doc_id: str) -> None:
        advice = " It can still be deleted from the run history." if kind == "run" else ""
        super().__init__(f"The stored {kind} '{doc_id}' cannot be read: its document is damaged or was written by "
                         f"an incompatible version.{advice}")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    document TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);
CREATE TABLE IF NOT EXISTS custom_tools (
    name TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    document TEXT NOT NULL
);
"""


# --- Connection -----------------------------------------------------------------------------------

@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """Open a connection, commit when the block succeeds, and always close it.

    WAL journaling lets other programs (a database browser, for example) read the file while the
    server writes to it.
    """
    with _lock:
        conn = sqlite3.connect(settings.db_path, timeout=30)
        # Text that is not UTF-8 (a hand-edited or foreign row) is decoded with replacement characters instead of
        # failing every query that reads it: startup recovery, the history and the plan list among them.
        conn.text_factory = lambda data: data.decode("utf-8", errors="replace")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db() -> None:
    """Create the data directory and the tables if they do not exist yet (called at startup)."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(_SCHEMA)


# --- Plans ----------------------------------------------------------------------------------------

def save_plan(plan: PlanResponse) -> None:
    """Insert a plan revision, or overwrite it when the id already exists."""
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO plans (id, created_at, document) VALUES (?, ?, ?)",
            (plan.id, plan.created_at.isoformat(), plan.model_dump_json()),
        )


def get_plan(plan_id: str) -> PlanResponse | None:
    """The stored plan revision, or None when the id is unknown. Raises DocumentUnreadable when the stored
    document no longer loads."""
    if not _can_store(plan_id):
        return None
    with connect() as conn:
        row = conn.execute("SELECT document FROM plans WHERE id = ?", (plan_id,)).fetchone()
    return _load(PlanResponse, row[0], "plan", plan_id) if row else None


def list_plans(limit: int = 50) -> list[PlanResponse]:
    """The most recent plan revisions, newest first. A document that cannot be read is left out (and logged),
    so one damaged or foreign plan cannot hide every other saved plan."""
    with connect() as conn:
        rows = conn.execute("SELECT document FROM plans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    plans = []
    for (document,) in rows:
        try:
            plans.append(PlanResponse.model_validate_json(document))
        except (ValueError, RecursionError) as exc:  # ValidationError is a ValueError
            log.warning("Skipping a plan document that cannot be read: %s", _first_line(exc))
    return plans


# --- Custom tools ---------------------------------------------------------------------------------

def add_custom_tool(tool: CustomTool, limit: int) -> str:
    """Register a custom tool: "added", "full" when `limit` tools are already registered, or "exists" when the
    name is taken. The count and the insert happen in one locked step, so two requests cannot both pass it. A row
    whose name the API cannot address (see _addressable_tool_name) is not counted: nothing could delete it."""
    with connect() as conn:
        count = sum(_addressable_tool_name(name) for (name,) in conn.execute("SELECT name FROM custom_tools"))
        if count >= limit:
            return "full"
        try:
            conn.execute("INSERT INTO custom_tools (name, created_at, document) VALUES (?, ?, ?)",
                         (tool.name, tool.created_at.isoformat(), tool.model_dump_json()))
        except sqlite3.IntegrityError:
            return "exists"
    return "added"


def list_custom_tools() -> list[CustomTool]:
    """Every registered custom tool, by name. A row whose document cannot be read, or holds a tool with another
    name than the row's, is left out (and logged): unreadable_custom_tools() names those rows."""
    return custom_tool_rows()[0]


def unreadable_custom_tools() -> list[str]:
    """The row names of the stored custom tools list_custom_tools() leaves out: the document cannot be read (it is
    damaged or was written by another version) or names another tool. They still count towards the limit and hold
    their name, so the Custom tools page lists them, and delete_custom_tool(row name) removes them."""
    return custom_tool_rows()[1]


def custom_tool_rows() -> tuple[list[CustomTool], list[str]]:
    """(the readable custom tools, the row names of the others), both by name, from one read of the table: what
    list_custom_tools() and unreadable_custom_tools() return. A row whose name the API cannot address is in
    neither (and logged), and add_custom_tool() does not count it."""
    with connect() as conn:
        rows = conn.execute("SELECT name, document FROM custom_tools ORDER BY name").fetchall()
    tools: list[CustomTool] = []
    unreadable: list[str] = []
    for name, document in rows:
        if not _addressable_tool_name(name):
            log.warning("The custom tool row %r has a name the API cannot address, so it is ignored", name)
            continue
        try:
            tool = CustomTool.model_validate_json(document)
        except (ValueError, TypeError, RecursionError) as exc:  # ValidationError is a ValueError
            log.warning("The custom tool %r cannot be read, so it is listed as unreadable: %s", name, _first_line(exc))
            unreadable.append(name)
            continue
        if tool.name != name:  # runs and the API look tools up by name, and deleting uses the row's name
            log.warning("The custom tool row %r holds a tool named %r, so it is listed as unreadable", name, tool.name)
            unreadable.append(name)
            continue
        tools.append(tool)
    return tools, unreadable


def _addressable_tool_name(name: object) -> bool:
    """False for a custom_tools row name no request can carry, so DELETE /api/tools/custom/{name} can never reach
    it: NULL or binary (a hand-edited row), and . or .. (browsers and HTTP clients resolve them as path steps, also
    when written %2E). Any other text can be sent percent-encoded; the add_custom_tool() count matches this."""
    # A TEXT name that is not valid UTF-8 is read with U+FFFD in it (connect()'s text_factory), so no request can
    # match its stored bytes either.
    return isinstance(name, str) and name not in (".", "..") and "\ufffd" not in name


def delete_custom_tool(name: str) -> bool:
    """Remove a custom tool by its row name. Returns False when no row has that name. Runs keep their own copy."""
    if not _can_store(name):
        return False
    with connect() as conn:
        cursor = conn.execute("DELETE FROM custom_tools WHERE name = ?", (name,))
    return cursor.rowcount > 0


# --- Runs -----------------------------------------------------------------------------------------

def save_run(run: Run) -> None:
    """Insert a run, or overwrite it. The pipeline calls this at every stage transition."""
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO runs (id, created_at, target, status, document) VALUES (?, ?, ?, ?, ?)",
            (run.id, run.created_at.isoformat(), run.target, run.status, run.model_dump_json()),
        )


def get_run(run_id: str) -> Run | None:
    """The stored copy of a run, or None when the id is unknown (see RunManager.get for live runs). Raises
    DocumentUnreadable when the stored document no longer loads: the history lists such a run (list_runs reads
    the raw JSON), so opening it must explain why it cannot be shown."""
    if not _can_store(run_id):
        return None
    with connect() as conn:
        row = conn.execute("SELECT document FROM runs WHERE id = ?", (run_id,)).fetchone()
    return _load(Run, row[0], "run", run_id) if row else None


def count_runs() -> dict[str, int]:
    """How many runs are stored, per status, for the totals on the dashboard's Overview page (the run list
    itself is capped). Counted the way list_runs shows them: the status in the document (or the row's, see
    _listed_status), "unreadable" when the document is not JSON, and rows whose id the API cannot address left
    out."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT CASE WHEN NOT json_valid(document) THEN 'unreadable' "
            "WHEN json_extract(document, '$.status') IN ('queued', 'running') AND status NOT IN ('queued', 'running') "
            "THEN status ELSE json_extract(document, '$.status') END, "
            "COUNT(*) FROM runs WHERE typeof(id) = 'text' AND length(id) BETWEEN 1 AND 64 "
            "AND id NOT GLOB '*[^A-Za-z0-9_-]*' GROUP BY 1").fetchall()
    counts: dict[str, int] = {}
    for status, count in rows:
        key = status if isinstance(status, str) else "unreadable"
        counts[key] = counts.get(key, 0) + count
    return counts


def delete_run(run_id: str) -> bool:
    """Delete a run. Returns False when no run had that id."""
    if not _can_store(run_id):
        return False
    with connect() as conn:
        cursor = conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        return cursor.rowcount > 0


def fail_stale_runs(reason: str = "The server restarted before this run finished.",
                    summarize: Callable[..., RunSummary] | None = None) -> int:
    """Mark runs that were queued or running when the process stopped as failed. Returns how many.

    Their worker threads died with the old process, so without this they would show "running" forever.
    Called once at startup. `summarize` (hybrid.summarize, passed in by main.py because the pipeline
    module imports this one) recomputes the summary from what the finished stages saved, so the run's
    KPIs and reports count its ports and findings instead of zeros. Because this runs at startup, a
    document that cannot be read must not stop the server from starting: only its status is changed.
    """
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, document FROM runs WHERE status IN ('queued', 'running') OR (json_valid(document) "
            "AND json_extract(document, '$.status') IN ('queued', 'running'))").fetchall()
        for run_id, stored in rows:
            try:
                document = _failed_run_document(stored, reason, summarize)
            except (ValueError, TypeError, ArithmeticError, RecursionError) as exc:  # ValidationError: ValueError
                log.warning("Run %s cannot be read, so only its status is set to failed: %s", run_id, _first_line(exc))
                document = _failed_raw_document(stored, reason)
            conn.execute("UPDATE runs SET status = 'failed', document = ? WHERE id = ?", (document, run_id))
    return len(rows)


def _failed_run_document(document: str, reason: str, summarize: Callable[..., RunSummary] | None) -> str:
    """A stale run document marked failed for `reason`: unfinished stages failed, duration and summary set."""
    run = Run.model_validate_json(document)
    now = datetime.now(timezone.utc)
    run.status = "failed"
    run.error = reason
    run.finished_at = now
    if run.started_at:
        # HybridSec writes aware times; a naive one in a hand-edited document is taken as UTC.
        started = run.started_at if run.started_at.tzinfo else run.started_at.replace(tzinfo=timezone.utc)
        run.duration_seconds = round((now - started).total_seconds(), 3)
    for stage in run.stages:
        if stage.status in {"pending", "running"}:
            stage.status = "failed"
            stage.error = reason
    if summarize is not None:
        with suppress(Exception):  # a summary that cannot be computed keeps the stored one
            run.summary = summarize(run, failed=True)
    run.log.append(f"[{now.isoformat(timespec='seconds')}] {reason}")
    return run.model_dump_json()


def _failed_raw_document(document: str, reason: str) -> str:
    """A stale document that does not load as a Run, with "status" and "error" set in its raw JSON, so the
    history (which reads the raw JSON) stops showing it as running. Anything that is not a JSON object is
    returned unchanged: the history lists it as unreadable anyway."""
    try:
        data = json.loads(document)
        if not isinstance(data, dict):
            return document
        data["status"] = "failed"
        data["error"] = reason
        return json.dumps(data)
    except (ValueError, TypeError, RecursionError):  # this runs at startup: it must never raise
        return document


def _load(model: type[PlanResponse] | type[Run], document: str, kind: str, doc_id: str):
    """Validate a stored document, turning a failure into DocumentUnreadable (logged with its first line)."""
    try:
        return model.model_validate_json(document)
    except (ValueError, RecursionError) as exc:  # ValidationError is a ValueError
        log.warning("The stored %s %s cannot be read: %s", kind, doc_id, _first_line(exc))
        raise DocumentUnreadable(kind, doc_id) from exc


def _can_store(key: str) -> bool:
    """False for an id or name SQLite cannot be given: a lone surrogate (which JSON allows, as \\ud800) has no
    UTF-8 form. No stored row can have such a key, so callers answer as for an unknown one (404, not 500)."""
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _first_line(exc: BaseException) -> str:
    """The first line of an exception's message (a ValidationError spans several), or its class name."""
    lines = str(exc).splitlines()
    return lines[0] if lines else type(exc).__name__


def list_runs(limit: int = 200) -> list[RunListItem]:
    """The most recent runs without their findings, newest first.

    Reads the raw JSON instead of validating a full Run for every row, which keeps the history list fast
    and tolerates documents saved by older versions (missing fields fall back to defaults). A document that
    cannot be read is listed with the status "unreadable" (from the row's own columns), so the history still
    counts it and the operator can delete it; one damaged or foreign document never takes the list down.
    """
    with connect() as conn:
        rows = conn.execute("SELECT id, created_at, target, status, document FROM runs ORDER BY created_at DESC "
                            "LIMIT ?", (limit,)).fetchall()
    items = []
    for run_id, created_at, target, column_status, document in rows:
        if not (isinstance(run_id, str) and _ID_RE.fullmatch(run_id)):
            log.warning("The run row %r has an id the API cannot address, so the history leaves it out", run_id)
            continue
        try:
            data = json.loads(document)
            if not isinstance(data, dict):  # null, a list, a number or a string: valid JSON, but no run
                raise TypeError(f"the document is a JSON {type(data).__name__}, not an object")
            item = RunListItem(
                id=run_id,  # the row's id, which opening, deleting and counting use, whatever the document says
                label=data.get("label"),
                target=data["target"],
                status=_listed_status(data["status"], column_status),
                mode=data.get("mode", "live"),
                tools=data.get("tools", []),
                profiles=data.get("profiles"),
                created_at=data["created_at"],
                duration_seconds=data.get("duration_seconds"),
                summary=data.get("summary"),  # the model maps null or a non-object to the default
            )
            item.model_dump_json()  # text that cannot be sent (a lone surrogate) must not fail the whole list
        except (ValueError, KeyError, TypeError, ArithmeticError, RecursionError) as exc:  # ValidationError
            # and PydanticSerializationError are ValueErrors; a deeply nested document raises RecursionError.
            log.warning("Run %s cannot be read, so the history lists it as unreadable: %s", run_id, _first_line(exc))
            item = _unreadable_item(run_id, created_at, target)
            if item is None:
                continue
        items.append(item)
    return items


def _listed_status(document_status: object, column_status: object) -> object:
    """The status the history shows: the document's, except when the document still says queued or running but
    its row does not. Startup recovery then marked the run failed in the row and could not rewrite the
    document (it was too deeply nested to write back), and showing it as running would keep it undeletable."""
    if document_status in ("queued", "running") and column_status not in ("queued", "running"):
        return column_status
    return document_status


def _unreadable_item(run_id: str, created_at: object, target: object) -> RunListItem | None:
    """The history entry of a run whose document cannot be read, built from the row's columns (a creation time
    that cannot be read shows as the epoch), or None when even that cannot be shown."""
    try:
        stamp = datetime.fromisoformat(str(created_at))
    except ValueError:
        stamp = datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        item = RunListItem(id=run_id, label=None, target=str(target), status="unreadable", mode="live", tools=[],
                           created_at=stamp, duration_seconds=None, summary=None)
        item.model_dump_json()
        return item
    except (ValueError, TypeError):
        log.warning("Run %s is left out of the history: even its target cannot be shown", run_id)
        return None


def to_list_item(run: Run) -> RunListItem:
    """The history-list view of a full run (used by the run comparison)."""
    return RunListItem(
        id=run.id, label=run.label, target=run.target, status=run.status, mode=run.mode, tools=run.tools,
        profiles=run.profiles, created_at=run.created_at, duration_seconds=run.duration_seconds,
        summary=run.summary,
    )
