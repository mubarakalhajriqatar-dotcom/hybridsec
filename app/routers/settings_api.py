"""Settings API: lets the operator configure the planner key and the scan limits from the dashboard.

Changes are written to the .env file (see envfile.py) and take effect on the next request, because
settings are re-read on every request. Secrets are never returned, only whether a key is configured. The
endpoints answer only to requests from the machine running HybridSec, even when the server listens on the
network; the Host and Origin checks in main.py additionally block DNS-rebinding and cross-site requests.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..config import ENV_FILE, settings
from ..envfile import EnvValueError, update_env_file, validate_value
from ..planner import create_plan
from ..schemas import PlanRequest
from ..security import TargetError, validate_allowlist_entry

router = APIRouter(prefix="/api/settings", tags=["Settings"])

# Characters and length that real API keys use. Anything else is almost certainly a copy-paste accident.
_API_KEY_RE = re.compile(r"^[A-Za-z0-9_\-.:]{8,512}$")


# --- Models ---------------------------------------------------------------------------------------

class SettingsView(BaseModel):
    """The current configuration as the Settings page shows it. API keys appear only as configured yes/no."""

    env_file: str = Field(description="Path of the .env file that changes are written to; empty when disabled.")
    env_file_writable: bool = Field(description="False when HYBRIDSEC_ENV_FILE is empty, which disables editing.")
    ai_provider_setting: str = Field(description="Configured provider: auto, anthropic, openai or rules.")
    ai_provider_resolved: str = Field(description="Provider that will actually be used (auto resolved).")
    ai_model: str | None = Field(description="Model the resolved provider will use; null for rules.")
    anthropic_key_configured: bool
    anthropic_key_source: Literal["env_file", "environment"] | None = Field(
        default=None, description="Where the Anthropic key in force comes from: the .env file, or the server's "
                                  "process environment (which clearing the key here cannot remove).")
    anthropic_model: str
    openai_key_configured: bool
    openai_key_source: Literal["env_file", "environment"] | None = Field(
        default=None, description="Where the OpenAI-compatible key in force comes from (see anthropic_key_source).")
    openai_model: str
    openai_base_url: str = Field(description="Base URL of the OpenAI-compatible endpoint.")
    allowed_targets: list[str] = Field(description="Target allow-list. Empty means any target the operator "
                                                   "confirms as authorized.")
    allow_simulation: bool
    max_timeout_seconds: int
    default_timeout_seconds: int
    max_top_ports: int
    max_concurrent_runs: int
    environment_settings: dict[str, str] = Field(
        default_factory=dict,
        description="Settings whose value in force comes from the server's process environment, as field -> "
                    "variable name. A blank value saved here cannot override them (a blank .env line never "
                    "masks the environment), so the dashboard warns instead of reporting them as saved.")


# The .env key each SettingsUpdate field writes (see _env_changes).
FIELD_KEYS = {
    "ai_provider": "HYBRIDSEC_AI_PROVIDER", "anthropic_api_key": "ANTHROPIC_API_KEY",
    "anthropic_model": "ANTHROPIC_MODEL", "openai_api_key": "OPENAI_API_KEY", "openai_model": "OPENAI_MODEL",
    "openai_base_url": "OPENAI_BASE_URL", "allowed_targets": "HYBRIDSEC_ALLOWED_TARGETS",
    "allow_simulation": "HYBRIDSEC_ALLOW_SIMULATION", "max_timeout_seconds": "HYBRIDSEC_MAX_TIMEOUT",
    "default_timeout_seconds": "HYBRIDSEC_DEFAULT_TIMEOUT", "max_top_ports": "HYBRIDSEC_MAX_TOP_PORTS",
    "max_concurrent_runs": "HYBRIDSEC_MAX_CONCURRENT_RUNS",
}


class SettingsUpdate(BaseModel):
    """Every field is optional: omitted fields stay as they are. Send an empty string to clear a key."""

    ai_provider: Literal["auto", "anthropic", "openai", "rules"] | None = Field(
        default=None, description="auto uses the first provider with credentials (Anthropic: an API key, an "
                                  "auth token or an SDK login profile; then OpenAI with a key), falling back "
                                  "to rules.")
    anthropic_api_key: str | None = Field(default=None, max_length=512,
                                             description="Anthropic API key (sk-ant-...). Empty string clears it "
                                                         "from .env; a key set in the server's environment stays "
                                                         "in force (see anthropic_key_source).")
    anthropic_model: str | None = Field(default=None, max_length=100)
    openai_api_key: str | None = Field(default=None, max_length=512,
                                          description="OpenAI or compatible API key. Empty string clears it from "
                                                      ".env; a key set in the server's environment stays in force.")
    openai_model: str | None = Field(default=None, max_length=100)
    openai_base_url: str | None = Field(default=None, max_length=300,
                                           description="http(s) URL of an OpenAI-compatible endpoint.")
    allowed_targets: list[str] | None = Field(default=None, max_length=200,
                                                 description="Hosts, IPs, CIDRs or *.domain wildcards. An empty "
                                                             "list removes the restriction.")
    allow_simulation: bool | None = None
    max_timeout_seconds: int | None = Field(default=None, ge=10, le=86400)
    default_timeout_seconds: int | None = Field(default=None, ge=10, le=86400,
                                                   description="May not exceed max_timeout_seconds.")
    max_top_ports: int | None = Field(default=None, ge=1, le=65535)
    max_concurrent_runs: int | None = Field(default=None, ge=1, le=20)


class PlannerTestResult(BaseModel):
    """Outcome of a small planning request, used by the Settings page's "Test planner" button."""

    ok: bool = Field(description="True when the configured provider answered without falling back.")
    provider: str = Field(description="Planner that produced the answer.")
    model: str | None
    note: str | None = Field(description="Why the planner fell back to the rules engine, or a note about the "
                                         "provider's plan, such as a tool the model added that was removed from "
                                         "the workflow.")
    summary: str
    steps: list[str]
    elapsed_seconds: float


# --- Local-only guard -----------------------------------------------------------------------------

def _is_loopback(host: str) -> bool:
    """True for loopback addresses, including bracketed IPv6 and IPv4-mapped IPv6 (::ffff:127.0.0.1),
    which dual-stack servers report for IPv4 clients. Names such as "localhost" are not accepted."""
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return bool(mapped and mapped.is_loopback)


def peer_is_local(request: Request) -> bool:
    """True when the TCP peer is a loopback address. A dependency of its own, so the execute endpoint can ask
    without refusing (a run with custom tools needs a local peer, other runs do not)."""
    return _is_loopback(request.client.host if request.client else "")


def require_local(local: bool = Depends(peer_is_local)) -> None:
    """Dependency for every settings endpoint and every custom-tool endpoint: the TCP peer must be a loopback
    address.

    The peer address comes from the network connection itself, so unlike a header it cannot be forged by
    the client. (The test-suite overrides this dependency and peer_is_local, because its test client has no
    real address.)
    """
    if not local:
        raise HTTPException(status_code=403, detail="This is only available on the machine running HybridSec. "
                                                    "Open the dashboard on that machine.")


# --- Helpers --------------------------------------------------------------------------------------

def _settings_view() -> SettingsView:
    """The configuration in force. Re-reads .env first, so after a PUT it shows the values just written."""
    settings.reload()
    return SettingsView(
        env_file=str(ENV_FILE) if ENV_FILE is not None else "",
        env_file_writable=ENV_FILE is not None,
        ai_provider_setting=settings.ai_provider,
        ai_provider_resolved=settings.resolved_ai_provider(),
        ai_model=settings.ai_model(),
        anthropic_key_configured=bool(settings.anthropic_api_key),
        anthropic_key_source=settings.value_source("ANTHROPIC_API_KEY"),
        anthropic_model=settings.anthropic_model,
        openai_key_configured=bool(settings.openai_api_key),
        openai_key_source=settings.value_source("OPENAI_API_KEY"),
        openai_model=settings.openai_model,
        openai_base_url=settings.openai_base_url,
        allowed_targets=settings.allowed_targets,
        allow_simulation=settings.allow_simulation,
        max_timeout_seconds=settings.max_timeout_seconds,
        default_timeout_seconds=settings.default_timeout_seconds,
        max_top_ports=settings.max_top_ports,
        max_concurrent_runs=settings.max_concurrent_runs,
        environment_settings={field: key for field, key in FIELD_KEYS.items()
                              if settings.value_source(key) == "environment"},
    )


def _clean_api_key(value: str, label: str) -> str:
    """Trim whitespace and surrounding quotes (common when pasting), then check the key's shape."""
    value = value.strip().strip('"').strip("'")
    if value == "":
        return ""
    if not _API_KEY_RE.match(value):
        raise HTTPException(status_code=400, detail=f"{label} looks malformed (unexpected characters or length). "
                                                    "Paste the key exactly as the provider shows it.")
    return value


def _clean_text(value: str, label: str) -> str:
    value = value.strip()
    try:
        return validate_value(value, label)
    except EnvValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _clean_allowed_targets(entries: list[str]) -> list[str]:
    """Validate and normalise allow-list entries, skipping blanks and duplicates."""
    cleaned: list[str] = []
    for raw in entries:
        if not raw.strip():
            continue
        try:
            entry = validate_allowlist_entry(raw)
        except TargetError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid allowed target '{raw.strip()}': {exc}") from exc
        if entry not in cleaned:
            cleaned.append(entry)
    return cleaned


def _env_changes(update: SettingsUpdate) -> dict[str, str | None]:
    """Map the fields that were sent to the .env keys they set, validating each value on the way."""
    changes: dict[str, str | None] = {}
    if update.ai_provider is not None:
        changes["HYBRIDSEC_AI_PROVIDER"] = update.ai_provider
    if update.anthropic_api_key is not None:
        changes["ANTHROPIC_API_KEY"] = _clean_api_key(update.anthropic_api_key, "Anthropic API key")
    if update.anthropic_model is not None:
        changes["ANTHROPIC_MODEL"] = _clean_text(update.anthropic_model, "Anthropic model")
    if update.openai_api_key is not None:
        changes["OPENAI_API_KEY"] = _clean_api_key(update.openai_api_key, "OpenAI API key")
    if update.openai_model is not None:
        changes["OPENAI_MODEL"] = _clean_text(update.openai_model, "OpenAI model")
    if update.openai_base_url is not None:
        url = _clean_text(update.openai_base_url, "OpenAI base URL")
        if url and not re.fullmatch(r"https?://[^\s/]+\S*", url):  # a URL with spaces can never be used
            raise HTTPException(status_code=400, detail="OpenAI base URL must start with http:// or https:// "
                                                        "and contain no spaces.")
        changes["OPENAI_BASE_URL"] = url
    if update.allowed_targets is not None:
        changes["HYBRIDSEC_ALLOWED_TARGETS"] = ",".join(_clean_allowed_targets(update.allowed_targets))
    if update.allow_simulation is not None:
        changes["HYBRIDSEC_ALLOW_SIMULATION"] = "true" if update.allow_simulation else "false"
    if update.max_timeout_seconds is not None:
        changes["HYBRIDSEC_MAX_TIMEOUT"] = str(update.max_timeout_seconds)
    if update.default_timeout_seconds is not None:
        changes["HYBRIDSEC_DEFAULT_TIMEOUT"] = str(update.default_timeout_seconds)
    if update.max_top_ports is not None:
        changes["HYBRIDSEC_MAX_TOP_PORTS"] = str(update.max_top_ports)
    if update.max_concurrent_runs is not None:
        changes["HYBRIDSEC_MAX_CONCURRENT_RUNS"] = str(update.max_concurrent_runs)
    return changes


# --- Endpoints ------------------------------------------------------------------------------------

@router.get("", response_model=SettingsView, summary="Current configuration (secrets masked)",
            dependencies=[Depends(require_local)])
def get_settings() -> SettingsView:
    """The current configuration. API keys are reported only as configured or not."""
    return _settings_view()


@router.put("", response_model=SettingsView, summary="Update configuration and write .env",
            dependencies=[Depends(require_local)])
def put_settings(update: SettingsUpdate) -> SettingsView:
    """Validate the sent fields, write them to .env, and return the configuration now in force.

    Nothing is written unless every sent field is valid.
    """
    if ENV_FILE is None:
        raise HTTPException(status_code=400, detail="Editing is disabled because HYBRIDSEC_ENV_FILE is empty. "
                                                    "Set it to a file path (or unset it) and restart the server.")
    changes = _env_changes(update)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to update. Send at least one setting to change.")

    new_default = update.default_timeout_seconds or settings.default_timeout_seconds
    new_max = update.max_timeout_seconds or settings.max_timeout_seconds
    if new_default > new_max:
        raise HTTPException(status_code=400, detail="Default timeout cannot exceed the maximum timeout. "
                                                    "Lower the default or raise the maximum.")

    try:
        update_env_file(ENV_FILE, changes)
    except EnvValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"{ENV_FILE} is not saved as UTF-8, so it was not changed. "
                                                    "Save it as UTF-8 and try again.") from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not write {ENV_FILE}: {exc}. "
                                                    "Check that the file is writable.") from exc
    return _settings_view()


@router.post("/test-planner", response_model=PlannerTestResult,
             summary="Run a small planning request with the current provider",
             dependencies=[Depends(require_local)])
def test_planner() -> PlannerTestResult:
    """Send a small fixed planning request to the configured provider and report how it went."""
    started = time.monotonic()
    result = create_plan(PlanRequest(
        tools=["nmap", "whatweb"],
        objective="Connectivity test: plan a hybrid workflow that uses Nmap to find open ports and WhatWeb to "
                  "fingerprint the web services it discovers on an authorized lab host.",
    ))
    return PlannerTestResult(
        ok=result.note is None or result.provider != "rules",  # a note on a provider's own plan is not a fallback
        provider=result.provider,
        model=result.model,
        note=result.note,
        summary=result.plan.summary[:400],
        steps=[f"{s.order}. {s.tool} ({s.stage})" for s in result.plan.workflow],
        elapsed_seconds=round(time.monotonic() - started, 2),
    )
