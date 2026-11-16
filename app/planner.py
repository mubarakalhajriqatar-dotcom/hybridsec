"""AI planner: turns an objective plus a tool list into a structured hybrid-tool plan, and refines an
existing plan from operator feedback.

Backends, chosen by config.Settings.resolved_ai_provider():
  * anthropic - the official Anthropic SDK with JSON-schema structured output
  * openai    - any OpenAI-compatible chat completions endpoint, in JSON mode
  * rules     - a deterministic planner that needs no API key

Whatever a model returns is normalised before it is used (only the requested tools, one step each, stages
taken from the tool registry, authorization always required). If the provider fails for any reason, the
rules planner answers instead and the response carries a `note` saying why, so planning never blocks a run.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import settings
from .schemas import Plan, PlanRequest, PlanResponse, PlanStep, SafetyControls
from .tools.registry import DEFAULT_TOOLS, STAGE_ORDER, TOOLS, availability, default_profile, order_tools

log = logging.getLogger("hybridsec.planner")

# --- What the model is asked for ------------------------------------------------------------------

# The JSON schema a model's answer must match. It is written by hand instead of being generated from the
# pydantic models because structured-output modes accept only a strict subset of JSON Schema: every object
# closed with additionalProperties: false and every property listed as required.
PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "workflow", "inputs", "outputs", "safety_controls", "limitations"],
    "properties": {
        "summary": {"type": "string"},
        "workflow": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["order", "tool", "stage", "purpose", "inputs", "outputs", "command_template"],
                "properties": {
                    "order": {"type": "integer"},
                    "tool": {"type": "string", "enum": list(TOOLS)},
                    "stage": {"type": "string", "enum": list(STAGE_ORDER)},
                    "purpose": {"type": "string"},
                    "inputs": {"type": "array", "items": {"type": "string"}},
                    "outputs": {"type": "array", "items": {"type": "string"}},
                    "command_template": {"type": "string"},
                },
            },
        },
        "inputs": {"type": "array", "items": {"type": "string"}},
        "outputs": {"type": "array", "items": {"type": "string"}},
        "safety_controls": {
            "type": "object",
            "additionalProperties": False,
            "required": ["authorization_required", "scope_restrictions", "rate_limits", "data_handling"],
            "properties": {
                "authorization_required": {"type": "boolean"},
                "scope_restrictions": {"type": "array", "items": {"type": "string"}},
                "rate_limits": {"type": "array", "items": {"type": "string"}},
                "data_handling": {"type": "array", "items": {"type": "string"}},
            },
        },
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
}

def _default_flags(tool: str) -> str:
    """The options of a tool's default profile (from the registry), with a trailing space when there are any."""
    flags = default_profile(tool).flags
    return f"{flags} " if flags else ""


# The commands the pipeline runs with each tool's default profile (see hybrid.py; the options come from the
# registry, so the planner and the pipeline cannot drift apart). The model is shown these so that the command
# templates in a plan describe the real implementation rather than an imaginary one; a run may choose another
# catalogued profile, which its stage records.
EXECUTOR_COMMANDS = {
    "nmap": f"nmap {_default_flags('nmap')}--open --top-ports {{top_ports}} --host-timeout {{timeout}}s "
            "-oX - {target}",
    "whatweb": f"whatweb --color=never {_default_flags('whatweb')}--follow-redirect=same-site "
               "--log-json=<file> {url}",
    "nikto": f"nikto -h {{url}} {_default_flags('nikto')}-Format json -output <file> -maxtime {{timeout}}s "
             "-nointeractive -ask no",
}

SYSTEM_PROMPT = """You are the planning engine of HybridSec, a platform that chains established, open-source
security assessment tools into a single "hybrid" workflow for authorized testing only.

Produce a concrete plan that HybridSec's pipeline can execute. Rules:
- Use only the tools the user lists. Each workflow step maps to exactly one tool and one stage:
  nmap -> port_scan, whatweb -> web_fingerprint, nikto -> web_vuln_scan.
- Order steps so each one consumes the previous step's output: nmap's open web ports become the URLs
  that whatweb and nikto receive. HybridSec builds those URLs itself (http or https from the port and
  service banner) and caps web fingerprinting at 12 services per run.
- command_template must be the command HybridSec actually runs for that tool, copied from the list below
  with the placeholders {target}, {top_ports}, {url} and {timeout}. Do not add or change flags: HybridSec
  runs these commands as they are. Never suggest exploitation, brute force, credential guessing or
  denial-of-service options anywhere in the plan.
- safety_controls must require explicit authorization and describe scope, rate limiting and data handling.
- Write for a project report: precise, plain language, no marketing tone. The summary is two or three
  sentences. Keep each list item short.

Commands HybridSec executes:
""" + "\n".join(f"  {tool}: {cmd}" for tool, cmd in EXECUTOR_COMMANDS.items()) + """
These are the tools' default profiles. At run time the operator may pick another preset profile from HybridSec's
own fixed, non-exploitative catalogue (for example Nmap's default scripts or a higher WhatWeb aggression level),
which the run then records; the plan always shows the defaults."""


# --- Rules planner --------------------------------------------------------------------------------

# Template step for each tool, used by the rules planner. The stage comes from the tool registry.
_STEP_LIBRARY: dict[str, dict[str, Any]] = {
    "nmap": {
        "purpose": "Discover live hosts and open TCP ports, then identify the service and version behind each port.",
        "inputs": ["target host, IP or CIDR", "top_ports count"],
        "outputs": ["list of open ports with service, product and version", "list of candidate web services"],
        "command_template": EXECUTOR_COMMANDS["nmap"],
    },
    "whatweb": {
        "purpose": "Fingerprint every discovered web service: server software, frameworks, CMS, JavaScript "
                   "libraries and versions.",
        "inputs": ["URLs built from the open web ports found by the port scan"],
        "outputs": ["per-URL technology list with versions", "HTTP status and page title"],
        "command_template": EXECUTOR_COMMANDS["whatweb"],
    },
    "nikto": {
        "purpose": "Check each web service for dangerous files, outdated components and common misconfigurations.",
        "inputs": ["URLs of the web services that answered the fingerprint stage"],
        "outputs": ["list of findings with severity, description and reference"],
        "command_template": EXECUTOR_COMMANDS["nikto"],
    },
}


# How each tool contributes, for the summary of a rules plan.
_STEP_ROLE = {
    "nmap": "establishes the attack surface (live hosts, open ports and the services behind them)",
    "whatweb": "fingerprints the web services (server software, frameworks, CMS and their versions)",
    "nikto": "checks the web services for dangerous files, outdated components and misconfigurations",
}
_STANDARD_PORTS_INPUT = "URLs built from the target's standard web ports 80 and 443 (this workflow has no port scan)"


def _role(tool: str) -> str:
    """How a tool contributes, for a rules plan's summary; a tool added to the registry without a _STEP_ROLE
    sentence is described by its stage instead of breaking the plan."""
    return _STEP_ROLE.get(tool) or f"runs the {TOOLS[tool].stage.replace('_', ' ')} stage"


def _step_inputs(tool: str, tools: list[str]) -> list[str]:
    """What a step consumes in this workflow, as the pipeline really hands it over: a web stage gets the port
    scan's web ports, Nikto the URLs that answered WhatWeb, and without a port scan (hybrid._web_targets) the
    target's standard web ports 80 and 443."""
    if tool == "whatweb":
        return list(_STEP_LIBRARY[tool]["inputs"]) if "nmap" in tools else [_STANDARD_PORTS_INPUT]
    if tool == "nikto":
        if "whatweb" in tools:
            return list(_STEP_LIBRARY[tool]["inputs"])
        if "nmap" in tools:
            return list(_STEP_LIBRARY["whatweb"]["inputs"])
        return [_STANDARD_PORTS_INPUT]
    return list(_STEP_LIBRARY[tool]["inputs"])


def _rules_summary(tools: list[str], target: str) -> str:
    """Two sentences that describe the workflow as the pipeline runs it: a single tool has no later stages
    to enrich, and a workflow without a port scan probes the target's standard web ports."""
    names = " + ".join(TOOLS[t].display_name for t in tools)
    first = TOOLS[tools[0]].display_name
    if len(tools) == 1:
        probes = ("" if tools[0] == "nmap"
                  else "; without a port scan, the target's standard web ports 80 and 443 are probed")
        return (f"An assessment tool that runs {names} as a single-stage pipeline against {target}. "
                f"{first} {_role(tools[0])}{probes}, and the operator receives the result as one report "
                "with a risk score and highlights.")
    opening = (f"{first} {_role(tools[0])}" if "nmap" in tools
               else f"Without a port scan, the target's standard web ports 80 and 443 are probed: {first} "
                    f"{_role(tools[0])}")
    return (f"A hybrid assessment tool that chains {names} into one pipeline against {target}. {opening}, and "
            "each later stage enriches the previous stage's results so the operator receives a single "
            "correlated report instead of separate tool outputs.")


def _plan_inputs(tools: list[str]) -> list[str]:
    """What the operator supplies: a network range and a top-ports count only make sense with a port scan
    (without one, the web stages probe a single host's standard web ports)."""
    target = ("target (IP, hostname or small CIDR)" if "nmap" in tools
              else "target (one IP address or hostname; a network range needs a port scan)")
    inputs = [target, "explicit authorization confirmation", "time budget in seconds"]
    if "nmap" in tools:
        inputs.append("number of top ports to probe")
    return inputs


_RESULT_PARTS = (("nmap", "ports"), ("whatweb", "web technologies"), ("nikto", "findings"))


def _plan_outputs(tools: list[str]) -> list[str]:
    """What the run produces: only the result types its tools collect."""
    parts = ", ".join(name for tool, name in _RESULT_PARTS if tool in tools)
    result = f"correlated JSON result ({parts})" if len(tools) > 1 else f"JSON result ({parts})"
    return [result, "risk score and highlights", "downloadable CSV, HTML and Markdown reports",
            "run history for comparison over time"]


def _plan_rate_limits(tools: list[str]) -> list[str]:
    """The pipeline's limits, with a line for the tools this workflow actually runs."""
    per_tool = []
    if "nmap" in tools:
        per_tool.append("Nmap limited to the top N ports")
    if "whatweb" in tools:
        per_tool.append("WhatWeb aggression level 1 by default (one request per URL)")
    if "nikto" in tools:
        per_tool.append("Nikto stopped by its -maxtime limit on every URL")
    profiles = "any other profile comes from HybridSec's fixed, non-exploitative catalogue."
    return ["Single sequential pipeline per run; concurrent runs are capped.",
            "Hard timeout per run and per stage.",
            "; ".join([*per_tool, profiles]) if per_tool else profiles[0].upper() + profiles[1:]]


def _plan_limitations(tools: list[str]) -> list[str]:
    """What the results cannot show, for the tools this workflow runs."""
    limitations = []
    if "nmap" in tools or "whatweb" in tools:
        limitations.append("Service versions come from banners and may be inaccurate.")
    if "nmap" in tools:
        limitations.append("Hosts that block ICMP and SYN probes may appear closed.")
    else:
        limitations.append("Without a port scan, only the standard web ports 80 and 443 are probed.")
    if "whatweb" in tools:
        limitations.append("WhatWeb fingerprints only the landing page of each service.")
    if "nikto" in tools:
        limitations.append("Nikto findings are graded by keywords, so their severity is an estimate.")
    return limitations


def rules_plan(request: PlanRequest) -> Plan:
    """A deterministic plan assembled from templates. It needs no API key and never fails, which makes it
    the default without a provider and the fallback when a provider errors."""
    tools = order_tools(request.tools) or list(DEFAULT_TOOLS)
    workflow = []
    for index, tool in enumerate(tools, start=1):
        entry = {**_STEP_LIBRARY[tool], "inputs": _step_inputs(tool, tools)}
        workflow.append(PlanStep(order=index, tool=tool, stage=TOOLS[tool].stage, **entry))
    return Plan(
        summary=_rules_summary(tools, request.target_hint or "an authorized target"),
        workflow=workflow,
        inputs=_plan_inputs(tools),
        outputs=_plan_outputs(tools),
        safety_controls=SafetyControls(
            authorization_required=True,
            scope_restrictions=["Targets must be owned by the operator or covered by written permission.",
                                "Optional allow-list (HYBRIDSEC_ALLOWED_TARGETS) limits what can be scanned.",
                                "CIDR ranges larger than /24 are rejected."],
            rate_limits=_plan_rate_limits(tools),
            data_handling=["Results stored locally in SQLite only.",
                           "No raw credentials are collected; only service banners and headers.",
                           "Runs can be deleted from the dashboard."],
        ),
        limitations=_plan_limitations(tools),
    )


# --- Prompts --------------------------------------------------------------------------------------

def _tool_lines(tools: list[str]) -> str:
    installed = availability()
    return "\n".join(
        f"- {TOOLS[t].display_name} ({t}): {TOOLS[t].description} "
        f"[{'installed' if installed.get(t) else 'not installed on this host yet'}]"
        for t in tools
    )


def _objective_section(request: PlanRequest) -> str:
    """The part every prompt starts with: the objective, the selected tools and the optional example target."""
    tools = order_tools(request.tools)
    hint = f"\nExample target supplied by the user: {request.target_hint}" if request.target_hint else ""
    return f"Objective:\n{request.objective}\n\nTools selected:\n{_tool_lines(tools)}{hint}\n\n"


def _user_prompt(request: PlanRequest) -> str:
    return _objective_section(request) + "Return the plan as JSON matching the required schema."


def _refine_prompt(parent: PlanResponse, feedback: str) -> str:
    return (
        _objective_section(parent.request)
        + f"Current plan (revision {parent.revision}) as JSON:\n{parent.plan.model_dump_json(indent=2)}\n\n"
        f"Operator feedback on this plan:\n{feedback}\n\n"
        "Produce the revised plan as JSON matching the required schema. Apply the feedback faithfully, keep "
        "everything that was not criticised, and keep the same tool set unless the feedback asks otherwise "
        "(the available tools are nmap, whatweb and nikto)."
    )


# --- Provider calls -------------------------------------------------------------------------------

def anthropic_plan(user_prompt: str) -> tuple[Plan, str]:
    """Ask Claude for a plan using JSON-schema structured output. Returns the plan and the model that answered.

    The request enables the API's server-side fallback: security-tooling prompts are sometimes declined by
    the configured model's safety classifier, and the API then continues on a fallback model.
    response.model names the model that actually answered, which the dashboard shows on the plan.
    """
    import anthropic  # imported here so the rest of the app works without the SDK installed

    # An empty key means "not configured in .env": pass None so the SDK can find ANTHROPIC_API_KEY,
    # ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile by itself.
    # HYBRIDSEC_AI_TIMEOUT limits each connect, read and write operation of the request, not the request as a
    # whole: httpx applies it per operation, so an answer that arrives in slow pieces can take longer. max_retries=0
    # makes one attempt; the SDK would otherwise retry twice, so a provider that hangs would hold the operator for
    # three times as long before the rules fallback.
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key or None, timeout=settings.ai_timeout_seconds,
                                 max_retries=0)
    response = client.beta.messages.create(
        model=settings.anthropic_model,
        max_tokens=8000,
        system=SYSTEM_PROMPT,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={"format": {"type": "json_schema", "schema": PLAN_SCHEMA}},
        messages=[{"role": "user", "content": user_prompt}],
    )
    if not hasattr(response, "stop_reason") or not isinstance(getattr(response, "content", None), list):
        # The SDK hands back the raw text when the body was not JSON, and a message without content when it was
        # JSON of another shape: a proxy, a portal or a wrong endpoint answered, not a model.
        raise RuntimeError(ANTHROPIC_NOT_MESSAGE)
    if response.stop_reason == "refusal":
        raise RuntimeError("The model declined to produce a plan for this objective.")
    text = next((block.text for block in response.content if block.type == "text"), "")
    plan = Plan.model_validate(json.loads(text))
    return plan, _answered_model(getattr(response, "model", None), settings.anthropic_model)


def openai_plan(user_prompt: str) -> tuple[Plan, str]:
    """Ask an OpenAI-compatible endpoint for a plan in JSON mode. Returns the plan and the model name.

    Uses plain HTTP rather than an SDK so that any compatible gateway (Azure, Ollama, LM Studio) works by
    changing OPENAI_BASE_URL. JSON mode does not enforce a schema, so the schema goes into the system prompt.
    """
    payload = {
        "model": settings.openai_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT + "\n\nRespond with a single JSON object that matches this "
                                          "JSON schema exactly:\n" + json.dumps(PLAN_SCHEMA)},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    headers = {"Content-Type": "application/json"}
    if settings.openai_api_key:
        # A local gateway (Ollama, LM Studio) needs no key; "Bearer " alone is not even a legal header value.
        headers["Authorization"] = f"Bearer {settings.openai_api_key}"
    # As for Anthropic, HYBRIDSEC_AI_TIMEOUT limits each connect, read and write operation, not the whole request.
    with httpx.Client(timeout=settings.ai_timeout_seconds) as client:
        resp = client.post(f"{settings.openai_base_url.rstrip('/')}/chat/completions", json=payload, headers=headers)
    if resp.status_code != 200:
        # describe_error() recognises the "HTTP <code>" part of this message; the provider's own message and
        # code follow on the same line, so a pretty-printed error body still reads as one sentence.
        raise RuntimeError(f"OpenAI-compatible endpoint returned HTTP {resp.status_code}: {_openai_error_text(resp)}")
    try:
        body = resp.json()
    except ValueError as exc:  # json.JSONDecodeError: an HTML page or an empty body
        raise RuntimeError(OPENAI_NOT_JSON) from exc
    choices = body.get("choices") if isinstance(body, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        # A gateway may answer 200 with an error object, or with no choice at all.
        error = body.get("error") if isinstance(body, dict) else None
        reason = error.get("message") if isinstance(error, dict) else error
        raise RuntimeError("The endpoint answered without a plan" + (f": {reason}" if reason else "."))
    choice = choices[0]
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = message.get("content")
    parts = content if isinstance(content, list) else []
    # A refusal or a content filter carries no usable plan, even when part of an answer came before the cut.
    if (message.get("refusal") or choice.get("finish_reason") == "content_filter"
            or any(isinstance(part, dict) and part.get("type") == "refusal" for part in parts)):
        raise RuntimeError("The model declined to produce a plan for this objective.")
    if isinstance(content, list):
        # Some gateways send the answer as content parts: [{"type": "text", "text": "{...}"}, ...].
        content = "".join(_part_text(part) for part in parts)
    if content is None or (isinstance(content, (str, dict)) and not content):
        raise RuntimeError("The model returned an empty answer instead of a plan.")
    if isinstance(content, dict):  # a gateway that already parsed the JSON answer
        plan = Plan.model_validate(content)
    elif isinstance(content, str):
        plan = Plan.model_validate(json.loads(content))
    else:
        raise RuntimeError(OPENAI_NOT_TEXT)
    return plan, _answered_model(body.get("model"), settings.openai_model)


def _part_text(part: Any) -> str:
    """The text of one content part: a plain string, or the "text" of a {"type": "text", "text": ...} part. Parts
    of other kinds (an image, a tool call) carry no plan text."""
    if isinstance(part, str):
        return part
    text = part.get("text") if isinstance(part, dict) else None
    return text if isinstance(text, str) else ""


def _openai_error_text(resp: Any) -> str:
    """The error an OpenAI-compatible endpoint returned, on one line: the message and code from its JSON body
    when there is one (OpenAI nests them under "error" and writes them over several lines; vLLM puts them at
    the top level), else the start of the raw text, or "(empty response)" when there is none."""
    try:
        body = resp.json()
    except Exception:  # not JSON
        body = None
    error = body.get("error") if isinstance(body, dict) else None
    if not (isinstance(error, dict) and error.get("message")) and isinstance(body, dict) and body.get("message"):
        error = body  # {"object": "error", "message": "...", "type": "NotFoundError", "code": 404}
    if isinstance(error, dict) and error.get("message"):
        code = error.get("code") or error.get("type")
        text = f"{error['message']}" + (f" ({code})" if code else "")
    elif isinstance(error, str) and error:
        text = error
    else:
        text = resp.text
    return " ".join(str(text).split())[:300] or "(empty response)"


def _answered_model(value: Any, configured: str) -> str:
    """The model name a provider reported, or the configured name when it reported none that is usable: a
    gateway may leave the field out or send null, an empty or blank name, or something that is not a name
    at all. The configured name is then the best description of what answered."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return configured


def _call_provider(provider: str, user_prompt: str) -> tuple[Plan, str]:
    if provider == "anthropic":
        return anthropic_plan(user_prompt)
    if provider == "openai":
        return openai_plan(user_prompt)
    raise ValueError(f"Unknown AI provider '{provider}'. Use anthropic or openai.")


def _normalize_plan(plan: Plan, request: PlanRequest, allowed_tools: list[str] | None = None) -> Plan:
    """Make a model's plan safe to execute: only allowed tools, one step per tool, stages from the registry.

    Steps are put in pipeline order (Nmap, WhatWeb, Nikto) and renumbered from 1. Every command template is
    set to the command the pipeline really runs (EXECUTOR_COMMANDS): a run executes the registry's profiles,
    never flags a model wrote, so a plan must not show any. authorization_required is always forced to true.
    `allowed_tools` defaults
    to the requested tools; refinement passes every known tool, so feedback such as "add Nikto" or
    "drop Nikto" can change the tool set. If nothing usable is left, ValueError is raised so the caller
    falls back to the rules planner (create) or keeps the previous revision (refine), with a note.
    The rate limits the model wrote for a tool it added are removed with that tool's step, because a safety
    control must not describe a tool that will not run (a line that also describes a tool that runs is kept, see
    _without_tools); create_plan's note names such tools (_added_tools_note), refine_plan a limitation line
    (_removed_tools_limitation).
    """
    allowed = order_tools(allowed_tools if allowed_tools is not None else request.tools)
    added = _added_tools(plan, allowed)
    by_tool: dict[str, PlanStep] = {}
    for step in sorted(plan.workflow, key=lambda s: s.order):
        tool = step.tool.lower().strip()
        if tool in allowed and tool not in by_tool:
            step.tool = tool
            step.stage = TOOLS[tool].stage
            step.command_template = EXECUTOR_COMMANDS[tool]
            by_tool[tool] = step
    cleaned = [by_tool[t] for t in allowed if t in by_tool]
    if not cleaned:
        raise ValueError("The model's plan used none of the allowed tools")
    for index, step in enumerate(cleaned, start=1):
        step.order = index
    plan.workflow = cleaned
    plan.safety_controls.authorization_required = True
    if added:
        plan.safety_controls.rate_limits = _without_tools(plan.safety_controls.rate_limits, added,
                                                          [step.tool for step in cleaned])
    return plan


def _added_tools(plan: Plan, allowed: list[str]) -> list[str]:
    """The tools a model's workflow names besides the `allowed` ones, each once, in the model's order."""
    added: list[str] = []
    for step in sorted(plan.workflow, key=lambda s: s.order):
        tool = step.tool.lower().strip()
        if tool and tool not in allowed and tool not in added:
            added.append(tool)
    return added


def _tool_label(tool: str) -> str:
    """A tool's display name, or a name the model invented as it wrote it (on one line and cut short)."""
    return TOOLS[tool].display_name if tool in TOOLS else " ".join(tool.split())[:40]


def _names_pattern(tools: list[str]) -> re.Pattern[str] | None:
    """A pattern that finds the tools' names (the name as written and the display name) as whole words, or None
    when there is no name to look for. A name shorter than three characters is not looked for, as it would match
    ordinary words."""
    names = {name for tool in tools for name in (tool, _tool_label(tool)) if len(name) >= 3}
    if not names:
        return None
    return re.compile(r"(?<!\w)(?:" + "|".join(map(re.escape, sorted(names))) + r")(?!\w)", re.IGNORECASE)


def _without_tools(lines: list[str], tools: list[str], running: list[str]) -> list[str]:
    """`lines` without what they say only about the removed `tools`. A line that names none of them stays as it is,
    and a line that names one of them but none of the `running` tools (the plan's workflow) is left out. A line
    that names both stays, because it is also true of a tool that runs: only its parts (split at semicolons, as the
    rules planner joins its limits) that name a removed tool and no running one are left out of it."""
    removed = _names_pattern(tools)
    if removed is None:
        return lines
    kept_names = _names_pattern(running)

    def names_running(text: str) -> bool:
        # A running tool's name counts only outside a removed name: "nmap" inside an invented "nmap-nse" does not.
        return kept_names is not None and bool(kept_names.search(removed.sub(" ", text)))

    kept = []
    for line in lines:
        if not removed.search(line):
            kept.append(line)
            continue
        if not names_running(line):
            continue
        parts = line.split(";")
        keep = [index for index, part in enumerate(parts) if not removed.search(part) or names_running(part)]
        text = ";".join(parts[index] for index in keep).strip()
        if not text:
            continue
        if line.rstrip().endswith(".") and not text.endswith("."):
            text += "."
        if keep[0] != 0:  # the line's first part was left out, so the part now in front starts the sentence
            text = text[0].upper() + text[1:]
        kept.append(text)
    return kept


def _listed_tools(tools: list[str]) -> str:
    """The tools' names for a sentence: "Nikto", "Nikto and sqlmap", or the first five and "N more"."""
    names = [_tool_label(tool) for tool in tools[:5]] + ([f"{len(tools) - 5} more"] if len(tools) > 5 else [])
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _added_tools_note(added: list[str]) -> str | None:
    """The plan note that names the tools a model added although they were not selected, or None."""
    if not added:
        return None
    one = len(added) == 1
    return (f"The model added {_listed_tools(added)}, which {'was' if one else 'were'} not among the selected tools, "
            f"so {'it was' if one else 'they were'} removed from the workflow. The plan's other text may still "
            f"mention {'it' if one else 'them'}.")


_REMOVED_LINE_RE = re.compile(r"The model's revision also named .+ removed from the workflow\.\s*$")


def _removed_tools_limitation(removed: list[str]) -> str:
    """The limitation line of a refined plan that names the tools the model's revision added although HybridSec
    cannot run them (a refined plan's note is kept for feedback that was not applied)."""
    one = len(removed) == 1
    return (f"The model's revision also named {_listed_tools(removed)}, which {'is' if one else 'are'} not part of "
            f"this plan; {'it was' if one else 'they were'} removed from the workflow.")


# --- Error wording --------------------------------------------------------------------------------

# Why a provider "answered" without reaching a model: a 200 whose body was not JSON, or not a message.
OPENAI_NOT_JSON = "The OpenAI-compatible endpoint answered with a page that is not JSON, so no model was reached."
ANTHROPIC_NOT_MESSAGE = "The Anthropic API answered with something that is not a message, so no model was reached."
# A model answer that is neither text, nor content parts, nor an already parsed object.
OPENAI_NOT_TEXT = "The model's answer was neither text nor a JSON object."

# The SDK's NotFoundError for an unknown model names it ("model: claude-x"); a wrong ANTHROPIC_BASE_URL path, or a
# proxy that answered instead of the API, gives a plain "Not Found" or an HTML page.
_NAMES_A_MODEL = re.compile(r"\bmodel\b", re.IGNORECASE)

# (exception classes, each a class name matched exactly against the exception's class and its bases, or a
#  (class name, pattern) pair for a class that counts only when its message matches the pattern; substrings of
#  its message; hint shown to the operator). The first entry that matches wins.
_ERROR_HINTS = [
    (("AuthenticationError",), ("HTTP 401", "invalid x-api-key", "Incorrect API key"),
     "The provider rejected the credentials. Check the API key on the Settings page, or the token or login "
     "profile in the environment."),
    (("PermissionDeniedError",), ("HTTP 403",),
     "The key is valid but not allowed to use this model or endpoint."),
    (("RateLimitError",), ("HTTP 429", "insufficient_quota", "credit balance"),
     "Rate limit reached or the account has no credit left."),
    # A 404 that names a model (the SDK's "model: claude-x", OpenAI's model_not_found code, Ollama's "model 'x' not
    # found, try pulling it first", vLLM's "The model `x` does not exist") is about the model name; any other 404
    # is about the path: the SDK's (Anthropic) or the OpenAI-compatible endpoint's.
    ((("NotFoundError", _NAMES_A_MODEL),),
     ("model_not_found",
      re.compile(r"HTTP 404.*\bmodel\b.*\b(?:not found|does not exist)\b", re.IGNORECASE | re.DOTALL)),
     "The configured model name is not available to this account."),
    (("NotFoundError",), (),
     "The API path was not found. Check ANTHROPIC_BASE_URL if the server's environment sets one, or a proxy in "
     "between."),
    ((), ("HTTP 404",),
     "The endpoint path was not found. Check the OpenAI base URL on the Settings page."),
    # A base URL that cannot be used is not a network failure: httpx raises UnsupportedProtocol when the scheme is
    # missing or not http(s), and InvalidURL when the rest is broken (http://127.0.0.1:abc/v1, http://[::1/v1).
    (("UnsupportedProtocol", "InvalidURL"), (),
     "Check the provider's base URL (the OpenAI base URL on the Settings page, or ANTHROPIC_BASE_URL): it must be a "
     "valid http:// or https:// URL (scheme, host and an optional numeric port)."),
    # httpx's TransportError and TimeoutException cover every network failure of the OpenAI-compatible path (a
    # dropped connection, a reset, a proxy refusal, a write or pool timeout); the SDK has its own two classes.
    (("APIConnectionError", "APITimeoutError", "TransportError", "TimeoutException", "ConnectError", "ReadTimeout",
      "ConnectTimeout"), (),
     "Could not reach the provider. Check the network, proxy or firewall."),
    (("ImportError",), (),
     "The provider's Python package is not installed. Install requirements.txt and restart the server."),
    (("FileNotFoundError",), (),
     "A file the provider client needs is missing. Check SSL_CERT_FILE and similar environment variables."),
    ((), ("Could not resolve authentication method",),
     "No Anthropic credentials were found. Add an API key on the Settings page, or choose another provider."),
    ((), (OPENAI_NOT_JSON,),
     "Check the OpenAI base URL on the Settings page, or a proxy or captive portal in between."),
    ((), (ANTHROPIC_NOT_MESSAGE,),
     "Check the network proxy, or ANTHROPIC_BASE_URL if the server's environment sets one."),
    (("ValidationError", "JSONDecodeError"), (OPENAI_NOT_TEXT,),
     "The model answered, but not in the expected JSON shape."),
]


def describe_error(exc: Exception) -> str:
    """One readable sentence about a provider failure for the dashboard, instead of a raw exception dump."""
    name = type(exc).__name__
    text = str(exc)
    short = _provider_message(exc, text) or (text.splitlines()[0] if text else name)
    short = short.strip()
    if len(short) >= 2 and short[0] == short[-1] == '"' and '"' not in short[1:-1]:
        short = short[1:-1].strip()  # a message wrapped in quotes as a whole (the SDK's TypeError)
    short = short or name
    if len(short) > 160:  # one short line: cut at a word boundary and say that something was left out
        cut = short[:157]
        if " " in cut[100:]:
            cut = cut.rsplit(" ", 1)[0]
        short = cut.rstrip(" ,;:.") + "..."
    sentence = short if short.endswith((".", "!", "?")) else short + "."
    # Class names are matched exactly (the exception's class or one of its bases): the SDK's NotFoundError,
    # an unknown model, must not be confused with Python's FileNotFoundError or ModuleNotFoundError. A class
    # decides before any message text: the text of a ValidationError quotes the model's own answer, and a web
    # scanning plan easily mentions "HTTP 401" without the credentials being at fault.
    names = {cls.__name__ for cls in type(exc).__mro__}
    # The Anthropic SDK wraps httpx's errors (UnsupportedProtocol in APIConnectionError), so there the cause's classes
    # count too. Only there: elsewhere a cause (a JSON error behind the app's own RuntimeError) must not decide.
    if "APIConnectionError" in names and exc.__cause__ is not None:
        names |= {cls.__name__ for cls in type(exc.__cause__).__mro__}
    hint = (next((h for classes, _, h in _ERROR_HINTS if any(_is_class(c, names, text) for c in classes)), "")
            or next((h for _, needles, h in _ERROR_HINTS if any(_matches(n, text) for n in needles)), ""))
    return f"{name}: {sentence} {hint}".strip()


def _is_class(spec: str | tuple[str, re.Pattern[str]], names: set[str], text: str) -> bool:
    """A hint's class matches when it is among the exception's class names, and its pattern (if it has one)
    matches the message."""
    if isinstance(spec, tuple):
        return spec[0] in names and bool(spec[1].search(text))
    return spec in names


def _matches(needle: str | re.Pattern[str], text: str) -> bool:
    """A hint needle matches as a substring, or as a regular expression when it is one."""
    return bool(needle.search(text)) if isinstance(needle, re.Pattern) else needle in text


# How the SDK writes an error from the API: "Error code: 404 - " and the body as a Python dict.
_SDK_ERROR_TEXT = re.compile(r"Error code: \d+ - ")


def _provider_message(exc: Exception, text: str) -> str | None:
    """The provider's own error message: from the SDK's parsed body when it has one, else from the SDK's text,
    which looks like "Error code: 401 - {'type': 'error', 'error': {... 'message': '...'}}". Python writes a
    message that contains an apostrophe in double quotes, so both quotings are read. Any other text is left
    alone: a gateway's error that embeds another error as a dict would lose its HTTP status, and a
    ValidationError quotes (and shortens) the model's own answer."""
    body = getattr(exc, "body", None)
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict) and isinstance(error.get("message"), str) and error["message"].strip():
        return error["message"]
    if not _SDK_ERROR_TEXT.match(text):
        return None
    match = re.search(r"""'message':\s*(?:'((?:[^'\\]|\\.)+)'|"((?:[^"\\]|\\.)+)")""", text)
    if match:
        found = match.group(1) if match.group(1) is not None else match.group(2)
        # Python escapes a quote of the other kind and a backslash (\' becomes '); other escapes stay as written.
        return re.sub(r"\\(['\"\\\\])", r"\1", found)
    return None


# --- Entry points ---------------------------------------------------------------------------------

def _plan_response(request: PlanRequest, plan: Plan, provider: str, model: str | None, note: str | None,
                   parent: PlanResponse | None = None, feedback: str | None = None) -> PlanResponse:
    """Wrap a plan as a new revision: revision 1 for a new plan, or the parent's revision plus one."""
    return PlanResponse(
        id=uuid.uuid4().hex[:12],
        provider=provider,
        model=_encodable(model),
        note=_encodable(note),
        created_at=datetime.now(timezone.utc),
        request=request,
        plan=Plan.model_validate(_encodable(plan.model_dump())),
        tools_available=availability(),
        parent_id=parent.id if parent else None,
        revision=(parent.revision + 1) if parent else 1,
        feedback=feedback,
    )


def _encodable(value: Any) -> Any:
    """Provider text that can always be saved and sent, for a string or every string in a list or dict. A JSON
    answer may hold a lone surrogate escape (a gateway that cut a string in the middle of an emoji); pydantic
    accepts it, but it cannot be encoded as UTF-8, so saving the plan would fail. It becomes "?"."""
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace").decode("utf-8")
    if isinstance(value, list):
        return [_encodable(item) for item in value]
    if isinstance(value, dict):
        return {key: _encodable(item) for key, item in value.items()}
    return value


def create_plan(request: PlanRequest) -> PlanResponse:
    """Plan a new workflow with the configured provider, falling back to the rules planner on any failure."""
    provider = settings.resolved_ai_provider()
    note: str | None = None
    model: str | None = None
    try:
        if provider == "rules":
            plan = rules_plan(request)
        else:
            plan, model = _call_provider(provider, _user_prompt(request))
            # Normalising drops the tools the operator did not select, and the note says so. On a refined plan only
            # a tool HybridSec does not have is dropped, and a limitation line names it: there a note means that the
            # feedback was not applied.
            note = _added_tools_note(_added_tools(plan, order_tools(request.tools)))
            plan = _normalize_plan(plan, request)
    except Exception as exc:  # bad key, no credit, network problem, malformed JSON: degrade gracefully
        log.warning("AI provider '%s' failed, using rules planner: %s", provider, exc)
        note = f"The {provider} planner failed. {describe_error(exc)} Used the built-in rules planner instead."
        provider, model = "rules", None
        plan = rules_plan(request)
    # The saved request must describe the plan that was actually produced: a model may leave a tool out.
    request = request.model_copy(update={"tools": [step.tool for step in plan.workflow]})
    return _plan_response(request, plan, provider, model, note)


def refine_plan(parent: PlanResponse, feedback: str) -> PlanResponse:
    """Produce the next revision of `parent` that applies the operator's free-text feedback.

    The rules planner cannot interpret feedback, so without an AI provider (or when the provider fails) the
    new revision repeats the parent's plan and its `note` explains why. The parent is never modified.
    Feedback may change the tool set, so only a tool HybridSec does not have is removed from the model's revision;
    a limitation line names it, and the outputs and rate limits that describe only that tool go with it.
    """
    provider = settings.resolved_ai_provider()
    note: str | None = None
    model: str | None = None
    if provider == "rules":
        plan = parent.plan.model_copy(deep=True)
        note = ("Refinement needs an AI provider: the rules engine cannot interpret free-text feedback. "
                "Set up an AI provider on the Settings page, then refine again.")
    else:
        try:
            plan, model = _call_provider(provider, _refine_prompt(parent, feedback))
            removed = _added_tools(plan, list(TOOLS))
            plan = _normalize_plan(plan, parent.request, allowed_tools=list(TOOLS))  # drops their rate limits too
            # The previous revision's own line, which a model copies when it keeps what was not criticised, is
            # true only of that revision: drop it, and add a line for this revision when it removed tools.
            plan.limitations = [line for line in plan.limitations if not _REMOVED_LINE_RE.match(line)]
            if removed:
                plan.outputs = _without_tools(plan.outputs, removed, [step.tool for step in plan.workflow])
                plan.limitations.append(_removed_tools_limitation(removed))
        except Exception as exc:
            log.warning("AI provider '%s' failed to refine plan %s: %s", provider, parent.id, exc)
            note = f"The {provider} planner failed. {describe_error(exc)} The previous revision was kept unchanged."
            provider, model = "rules", None
            plan = parent.plan.model_copy(deep=True)
    # The revision's request mirrors its workflow, so "Execute this plan" and the tool list stay truthful.
    request = parent.request.model_copy(update={"tools": [step.tool for step in plan.workflow]})
    return _plan_response(request, plan, provider, model, note, parent=parent, feedback=feedback)
