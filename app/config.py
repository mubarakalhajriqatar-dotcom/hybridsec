"""Application settings, read from the process environment and the project's .env file.

Every other module imports the single `settings` object defined at the bottom of this file. It is re-read
with settings.reload() on every request (see the request guard in main.py), so an operator can paste an
API key or change the target allow-list in .env without restarting the server. Non-empty values in .env
take precedence over the process environment, which is what people expect when they edit the file by hand.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import time
from collections.abc import Mapping
from pathlib import Path

from dotenv import dotenv_values

BASE_DIR = Path(__file__).resolve().parent.parent


def _resolve_env_file() -> Path | None:
    """Locate the .env file that settings are read from and that the Settings page writes to.

    HYBRIDSEC_ENV_FILE overrides the default <project>/.env, and an empty value disables the file
    entirely. The test-suite points it at a throwaway file so a developer's real .env (and any API key
    in it) is never read or modified by tests.
    """
    override = os.getenv("HYBRIDSEC_ENV_FILE")
    if override is None:
        return BASE_DIR / ".env"
    if not override.strip():
        return None
    return Path(override)


ENV_FILE: Path | None = _resolve_env_file()

log = logging.getLogger("hybridsec.config")


# --- Parsing helpers ------------------------------------------------------------------------------

def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    """1/true/yes/on (any case) mean True and anything else False; a missing or blank value uses the default."""
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    """An integer, or the default when the value is missing or not a number (a typo never stops the server)."""
    raw = env.get(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def host_without_port(value: str) -> str:
    """'host:port', '[::1]:8000', a bare name or a URL -> the lower-case host name without the port. Used for
    the Host allow-list here and for the request's Host and Origin headers in main.py, so the two always
    match. An allow-list entry written as a URL (http://hybridsec.lab:8000/) names its host, not 'http'."""
    value = (value or "").strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]  # a path, if any, is not part of the name
    if value.startswith("["):
        name = value[1:value.find("]")] if "]" in value else value
    else:
        name = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    # An IPv6 address has many spellings (2001:0db8::0001, 2001:db8:0:0:0:0:0:1) but one canonical form,
    # which browsers send: compare that, so an allow-list entry matches however it was written.
    if ":" in name:
        try:
            return ipaddress.IPv6Address(name).compressed
        except ValueError:
            pass
    return name


def _env_list(env: Mapping[str, str], name: str) -> list[str]:
    """A comma-separated list with blank items removed: "a, b,,c" becomes ["a", "b", "c"]."""
    raw = env.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


# --- Settings -------------------------------------------------------------------------------------

class Settings:
    """Every configuration value as a plain attribute, plus a few derived helpers.

    reload() refreshes the attributes in place. Because every module holds a reference to this one
    object, a reload is visible everywhere at once.
    """

    app_name = "HybridSec"
    version = "2.0.0"

    def __init__(self) -> None:
        self.reload()

    # --- Loading ----------------------------------------------------------------------------------

    def _environment(self) -> dict[str, str]:
        """The process environment, overlaid with the non-empty values from ENV_FILE."""
        env: dict[str, str] = dict(os.environ)
        file_keys: set[str] = set()
        for key, value in self._env_file_values().items():
            # A blank line such as "ANTHROPIC_API_KEY=" means "not set here", so it must not
            # mask a value that the process environment provides.
            if value is not None and value.strip() != "":
                env[key] = value
                file_keys.add(key)
        self._file_keys = file_keys
        return env

    def value_source(self, name: str) -> str | None:
        """Where the value in force for `name` comes from: "env_file" (a non-empty line in ENV_FILE),
        "environment" (the process environment of the server) or None when neither sets it. The Settings
        page cannot clear a value that comes from the environment: a blank line in .env never masks it."""
        if name in getattr(self, "_file_keys", set()):
            return "env_file"
        return "environment" if os.environ.get(name, "").strip() else None

    def _env_file_values(self) -> dict[str, str | None]:
        """The raw KEY=value pairs of ENV_FILE.

        On Windows the file is locked for a moment while the Settings page replaces it, so a read that fails
        is retried a few times; if it still fails, or the file is not valid UTF-8 (saved as ANSI or UTF-16 by a
        Windows editor), the values read last time are kept rather than letting one request or worker thread
        crash. At the very first load there is nothing to fall back on, so a bad encoding stops the start-up
        with a clear message instead of silently ignoring the file (an empty allow-list would mean allow-all).
        """
        if ENV_FILE is None or not ENV_FILE.exists():
            return {}
        last_error: Exception | None = None
        for _ in range(5):
            try:
                values = dict(dotenv_values(ENV_FILE))
            except UnicodeDecodeError as exc:  # not transient, so retrying cannot help
                if not hasattr(self, "data_dir"):  # first load at start-up: refuse to start rather than ignore .env
                    raise RuntimeError(f"{ENV_FILE} is not valid UTF-8 ({exc}). Save it as UTF-8.") from exc
                last_error = exc
                break
            except OSError as exc:
                last_error = exc
                time.sleep(0.02)
                continue
            self._env_file_cache = values
            return values
        log.warning("Could not read %s (%s); keeping the values read last time.", ENV_FILE, last_error)
        return getattr(self, "_env_file_cache", {})

    def reload(self) -> Settings:
        """Re-read the environment and .env and replace every setting. Returns self."""
        env = self._environment()

        # Server address, and the Host header allow-list that defeats DNS rebinding (see main.py).
        # The loopback names are always allowed; a wildcard bind address such as 0.0.0.0 is not a name.
        self.host: str = env.get("HYBRIDSEC_HOST", "127.0.0.1")
        self.port: int = _env_int(env, "HYBRIDSEC_PORT", 8000)
        hosts = {"localhost", "127.0.0.1", "::1", "[::1]"}
        bind = host_without_port(self.host)  # canonical, so 0:0:0:0:0:0:0:0 is recognised as "::"
        if bind not in {"0.0.0.0", "::", ""}:
            hosts.add(bind)
        # Entries may be written as "name:port" or "[::1]:port"; the Host check compares names only.
        hosts.update(host_without_port(h) for h in _env_list(env, "HYBRIDSEC_ALLOWED_HOSTS"))
        # run.sh / run.ps1 bind the shell's HYBRIDSEC_HOST ahead of .env, so that address must pass the
        # Host check even when .env still holds another value (such as the 127.0.0.1 .env.example ships).
        shell_host = host_without_port(os.environ.get("HYBRIDSEC_HOST", ""))
        if shell_host and shell_host not in {"0.0.0.0", "::"}:
            hosts.add(shell_host)
        self.allowed_hosts: set[str] = hosts

        # AI planner. Provider: auto | anthropic | openai | rules (see resolved_ai_provider).
        self.ai_provider: str = env.get("HYBRIDSEC_AI_PROVIDER", "auto").strip().lower() or "auto"
        self.anthropic_api_key: str = env.get("ANTHROPIC_API_KEY", "").strip()
        self.anthropic_model: str = env.get("ANTHROPIC_MODEL", "").strip() or "claude-opus-5-5"
        self.openai_api_key: str = env.get("OPENAI_API_KEY", "").strip()
        self.openai_model: str = env.get("OPENAI_MODEL", "").strip() or "gpt-4o-mini"
        self.openai_base_url: str = env.get("OPENAI_BASE_URL", "").strip() or "https://api.openai.com/v1"
        self.ai_timeout_seconds: int = max(1, _env_int(env, "HYBRIDSEC_AI_TIMEOUT", 120))

        # Scanning safety limits. A hand-edited .env can hold values the Settings page would refuse (zero,
        # a negative number, a default above the maximum); they are clamped to the range the Settings API
        # enforces, so a typo can never make every run request fail with a confusing error.
        self.allowed_targets: list[str] = _env_list(env, "HYBRIDSEC_ALLOWED_TARGETS")
        # Programs the Custom tools page may register; edited in .env only, like HYBRIDSEC_ALLOWED_HOSTS. Empty
        # means tools/custom.py's DEFAULT_PROGRAMS. Shells, interpreters and attack tools are refused regardless.
        # As written: a path entry pins that exact file, and on Linux and macOS a path's letter case matters (the
        # rules compare program names in lower case themselves).
        self.custom_programs: list[str] = _env_list(env, "HYBRIDSEC_CUSTOM_PROGRAMS")
        self.max_timeout_seconds: int = max(10, min(86400, _env_int(env, "HYBRIDSEC_MAX_TIMEOUT", 900)))
        self.default_timeout_seconds: int = min(self.max_timeout_seconds,
                                                max(10, _env_int(env, "HYBRIDSEC_DEFAULT_TIMEOUT", 180)))
        self.allow_simulation: bool = _env_bool(env, "HYBRIDSEC_ALLOW_SIMULATION", True)
        self.max_top_ports: int = max(1, min(65535, _env_int(env, "HYBRIDSEC_MAX_TOP_PORTS", 1000)))
        self.max_concurrent_runs: int = max(1, min(20, _env_int(env, "HYBRIDSEC_MAX_CONCURRENT_RUNS", 3)))

        # Storage. The data directory is fixed after the first load: moving the database while the
        # server runs would point every query at a file with no tables.
        if not hasattr(self, "data_dir"):
            self.data_dir: Path = Path(env.get("HYBRIDSEC_DATA_DIR") or str(BASE_DIR / "data"))
            self.data_dir.mkdir(parents=True, exist_ok=True)
        return self

    # --- Derived values ---------------------------------------------------------------------------

    @property
    def db_path(self) -> Path:
        """The SQLite database file inside the data directory."""
        return self.data_dir / "hybridsec.db"

    @property
    def dashboard_dir(self) -> Path:
        """The folder holding the static dashboard (index.html, app.js, styles.css)."""
        return BASE_DIR / "dashboard"

    def anthropic_credentials_present(self) -> bool:
        """True when the Anthropic SDK can authenticate: a key from .env or the environment, an
        ANTHROPIC_AUTH_TOKEN, or an `ant auth login` profile that the SDK finds by itself.

        The SDK is asked directly, because where it looks depends on the platform (APPDATA on Windows,
        ~/.config elsewhere) and on ANTHROPIC_CONFIG_DIR and ANTHROPIC_PROFILE."""
        if self.anthropic_api_key or os.getenv("ANTHROPIC_AUTH_TOKEN"):
            return True
        try:
            from anthropic.lib.credentials._constants import (
                _has_active_profile_config,
                _has_auto_discoverable_credentials,
            )
            return bool(_has_auto_discoverable_credentials() or _has_active_profile_config())
        except Exception:  # no SDK, or an unreadable profile folder: the SDK could not use a profile either
            return False

    def resolved_ai_provider(self) -> str:
        """The planner backend to use. An explicit choice wins; "auto" (or any unknown value) picks the
        first provider that has credentials, Anthropic then OpenAI, and otherwise the key-less rules planner."""
        if self.ai_provider in {"anthropic", "openai", "rules"}:
            return self.ai_provider
        if self.anthropic_credentials_present():
            return "anthropic"
        if self.openai_api_key:
            return "openai"
        return "rules"

    def ai_model(self) -> str | None:
        """The model name the resolved provider will use, or None for the rules planner."""
        provider = self.resolved_ai_provider()
        if provider == "anthropic":
            return self.anthropic_model
        if provider == "openai":
            return self.openai_model
        return None


# The one shared instance. Import it as `from .config import settings`.
settings = Settings()
