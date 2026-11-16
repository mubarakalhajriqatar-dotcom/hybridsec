"""AI planner endpoints: create a plan, list and fetch saved plans, and refine a plan with feedback.

The planning itself happens in planner.py. This router validates the tool names, saves every plan revision
with storage.save_plan(), and turns an unknown plan id into a 404 response.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import storage
from ..planner import create_plan, refine_plan
from ..schemas import PlanRequest, PlanResponse, RefineRequest
from ..tools.registry import TOOLS, describe_unknown_tools, unknown_tools

router = APIRouter(prefix="/api/ai", tags=["AI planner"])


def _saved_plan(plan_id: str) -> PlanResponse:
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found.")
    return plan


@router.post("/plan", response_model=PlanResponse, summary="Generate a hybrid-tool plan")
def plan(request: PlanRequest) -> PlanResponse:
    """Plan a workflow for the selected tools and save it, so it can be executed or refined later."""
    unknown = unknown_tools(request.tools)
    if unknown:
        raise HTTPException(status_code=400,
                            detail=f"Unknown tool(s): {describe_unknown_tools(unknown)}. "
                                   f"Supported: {', '.join(TOOLS)}.")
    if len(request.objective.strip()) < 10:
        # The schema's minimum length counts spaces; a blank objective would still reach the AI provider.
        raise HTTPException(status_code=400, detail="Objective must contain at least 10 characters of text, "
                                                    "not only spaces.")
    response = create_plan(request)
    storage.save_plan(response)
    return response


@router.get("/plans", response_model=list[PlanResponse], summary="List saved plans")
def plans(limit: int = 50) -> list[PlanResponse]:
    """Saved plan revisions, newest first. `limit` is kept between 1 and 200."""
    return storage.list_plans(limit=max(1, min(limit, 200)))


@router.get("/plans/{plan_id}", response_model=PlanResponse)
def get_plan(plan_id: str) -> PlanResponse:
    """One saved plan revision."""
    return _saved_plan(plan_id)


@router.post("/plans/{plan_id}/refine", response_model=PlanResponse,
             summary="Create a new revision of a plan from operator feedback")
def refine(plan_id: str, request: RefineRequest) -> PlanResponse:
    """Save the next revision of a plan from the operator's feedback. An AI provider applies the feedback; the
    rules planner cannot interpret it, so its revision repeats the plan with a note saying so. The original
    revision stays unchanged."""
    parent = _saved_plan(plan_id)
    feedback = request.feedback.strip()
    if len(feedback) < 3:
        # The schema's minimum length counts spaces; blank feedback would create a meaningless revision.
        raise HTTPException(status_code=400, detail="Feedback must contain at least 3 characters of text, "
                                                    "not only spaces.")
    revised = refine_plan(parent, feedback)
    storage.save_plan(revised)
    return revised
