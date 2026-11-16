"""Run history endpoints: list, fetch and delete runs, download reports, and compare two runs.

Single runs are read through hybrid.manager.get(), which returns the live in-memory copy while a run is
still executing and the saved copy otherwise, so the dashboard can poll a run as it progresses.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import PlainTextResponse

from .. import reports, storage
from ..compare import compare_runs
from ..hybrid import manager
from ..schemas import CompareResponse, Run, RunListItem

router = APIRouter(prefix="/api", tags=["Runs"])


def _existing_run(run_id: str) -> Run:
    run = manager.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


@router.get("/runs", response_model=list[RunListItem], summary="List runs, newest first")
def list_runs(response: Response, limit: int = 200) -> list[RunListItem]:
    """Run history without findings. `limit` is kept between 1 and 1000. The X-Total-Count header says how many
    runs are stored, so a client can tell when the list it received is not the whole history."""
    response.headers["X-Total-Count"] = str(sum(storage.count_runs().values()))
    return storage.list_runs(limit=max(1, min(limit, 1000)))


@router.get("/runs/{run_id}", response_model=Run)
def get_run(run_id: str) -> Run:
    """One run with everything it found so far."""
    return _existing_run(run_id)


@router.delete("/runs/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_run(run_id: str) -> Response:
    """Delete a finished run. A run that is still executing cannot be deleted."""
    if manager.is_active(run_id):
        raise HTTPException(status_code=409, detail="Run is still executing. Wait for it to finish, then delete it.")
    if not storage.delete_run(run_id):
        raise HTTPException(status_code=404, detail="Run not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/runs/{run_id}/report", summary="Download a report (json, csv, md, html)")
def report(run_id: str, format: str = "json", download: bool = True) -> Response:
    """Render a run as a report. With download=false the browser displays it instead of saving it."""
    fmt = format.lower()
    if fmt not in reports.FORMATS:
        raise HTTPException(status_code=400, detail=f"format must be one of {', '.join(reports.FORMATS)}.")
    run = _existing_run(run_id)
    body = reports.render(run, fmt)
    if fmt == "csv":
        body = "\ufeff" + body  # UTF-8 byte-order mark: Excel on Windows otherwise decodes the file as ANSI
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{reports.filename(run, fmt)}"'
    return PlainTextResponse(content=body, media_type=f"{reports.FORMATS[fmt]}; charset=utf-8", headers=headers)


@router.get("/compare", response_model=CompareResponse, summary="Compare two runs")
def compare(base: str, other: str) -> CompareResponse:
    """What changed from run `base` to run `other`: ports, technologies, findings and risk score."""
    base_run = manager.get(base)
    other_run = manager.get(other)
    if not base_run or not other_run:
        raise HTTPException(status_code=404, detail="One or both runs were not found.")
    return compare_runs(base_run, other_run)
