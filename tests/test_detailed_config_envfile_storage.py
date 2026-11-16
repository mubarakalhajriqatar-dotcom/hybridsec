"""Edge-case tests for configuration loading (app/config.py), the .env writer (app/envfile.py) and SQLite
persistence (app/storage.py).

One behaviour per test, named after the requirement it checks. The config tests write only to the private
.env that tests/test_api.py pointed HYBRIDSEC_ENV_FILE at (and restore it afterwards), the .env writer tests
use pytest's tmp_path, and the storage tests use the private test database and delete what they create.
No API key value is ever printed; the only key-like strings are obvious dummies kept in the process environment.
"""
from __future__ import annotations

import contextlib
import json
import os
import stat
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from dotenv import dotenv_values

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app import config, envfile, storage
from app.config import BASE_DIR, ENV_FILE, settings
from app.envfile import _ADDED_KEYS_HEADER, EnvValueError, format_value, update_env_file, validate_value
from app.schemas import (
    CustomTool,
    Plan,
    PlanRequest,
    PlanResponse,
    PlanStep,
    PortFinding,
    Run,
    RunSummary,
    SafetyControls,
    StageResult,
    VulnFinding,
    WebFinding,
)

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def test_suite_uses_a_private_env_file_and_data_directory():
    """The tests never touch the developer's real .env or run history: both paths point into a temporary folder."""
    private = Path(os.environ["HYBRIDSEC_ENV_FILE"]).resolve()
    assert private != (BASE_DIR / ".env").resolve()
    assert Path(ENV_FILE).resolve() == private
    assert settings.data_dir.resolve() == Path(os.environ["HYBRIDSEC_DATA_DIR"]).resolve()
    assert settings.data_dir.resolve() != (BASE_DIR / "data").resolve()


# --- Fixtures and helpers -------------------------------------------------------------------------

@pytest.fixture
def env_file(monkeypatch):
    """The private .env file. Its previous content (or absence) and the settings are restored afterwards, after
    every environment change the test made through monkeypatch has been undone."""
    path = Path(ENV_FILE)
    assert path.resolve() != (BASE_DIR / ".env").resolve()
    before = path.read_bytes() if path.exists() else None
    try:
        yield path
    finally:
        monkeypatch.undo()
        if before is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(before)
        settings.reload()


def reload_from(path: Path, text: str, encoding: str = "utf-8") -> config.Settings:
    """Replace the whole private .env with `text` and reload the settings from it."""
    path.write_text(text, encoding=encoding, newline="\n")
    return settings.reload()


@pytest.fixture
def no_stored_credentials(monkeypatch):
    """Pretend this machine has no `ant auth login` profile and no auth token, so "auto" starts from nothing.

    config.py asks the Anthropic SDK whether it can find a profile; the SDK's two discovery helpers are replaced
    so the answer does not depend on the developer's machine. The patched module is handed back to the test."""
    from anthropic.lib.credentials import _constants as sdk_credentials

    monkeypatch.setattr(sdk_credentials, "_has_active_profile_config", lambda: False)
    monkeypatch.setattr(sdk_credentials, "_has_auto_discoverable_credentials", lambda: False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    return sdk_credentials


# --- config: precedence and file handling ---------------------------------------------------------

def test_blank_env_file_values_do_not_mask_the_process_environment(env_file, monkeypatch):
    """KEY=, KEY='' and KEY=   all mean "not set here", so a value from the process environment still applies."""
    monkeypatch.setenv("HYBRIDSEC_MAX_TOP_PORTS", "500")
    for blank in ("HYBRIDSEC_MAX_TOP_PORTS=\n", "HYBRIDSEC_MAX_TOP_PORTS=''\n", "HYBRIDSEC_MAX_TOP_PORTS=   \n"):
        assert reload_from(env_file, blank).max_top_ports == 500, blank
    assert reload_from(env_file, "HYBRIDSEC_MAX_TOP_PORTS=600\n").max_top_ports == 600  # a real value wins


def test_env_file_accepts_export_prefix_and_quoted_values(env_file):
    """Shell-style "export KEY=value" lines and quoted values are read; lists are split on commas and trimmed."""
    loaded = reload_from(env_file, "export HYBRIDSEC_MAX_TOP_PORTS=222\n"
                                   "HYBRIDSEC_ALLOWED_TARGETS='10.10.20.0/24, *.lab.example.edu,,'\n"
                                   'HYBRIDSEC_HOST="10.10.20.5"\n')
    assert loaded.max_top_ports == 222
    assert loaded.allowed_targets == ["10.10.20.0/24", "*.lab.example.edu"]
    assert loaded.host == "10.10.20.5" and "10.10.20.5" in loaded.allowed_hosts


def test_env_file_with_a_byte_order_mark_is_read_from_its_first_line(env_file):
    """A .env saved by an editor that adds a UTF-8 BOM still applies the setting on its first line."""
    assert reload_from(env_file, "HYBRIDSEC_MAX_TOP_PORTS=321\n", encoding="utf-8-sig").max_top_ports == 321
    assert env_file.read_bytes().startswith(b"\xef\xbb\xbf")


def test_missing_or_disabled_env_file_falls_back_to_the_process_environment(env_file, monkeypatch, tmp_path):
    """HYBRIDSEC_ENV_FILE naming a file that does not exist, or no file at all, leaves the environment in charge."""
    monkeypatch.setenv("HYBRIDSEC_MAX_TOP_PORTS", "321")
    missing = tmp_path / "does-not-exist.env"
    monkeypatch.setattr(config, "ENV_FILE", missing)
    assert settings.reload().max_top_ports == 321
    assert not missing.exists()  # reading settings never creates the file
    monkeypatch.setattr(config, "ENV_FILE", None)
    assert settings.reload().max_top_ports == 321
    monkeypatch.delenv("HYBRIDSEC_MAX_TOP_PORTS")
    assert settings.reload().max_top_ports == 1000  # the built-in default


def test_resolve_env_file_rules(monkeypatch, tmp_path):
    """Unset means <project>/.env, a blank value disables the file, any other value is the path (nothing is read)."""
    monkeypatch.delenv("HYBRIDSEC_ENV_FILE")
    assert config._resolve_env_file() == BASE_DIR / ".env"
    monkeypatch.setenv("HYBRIDSEC_ENV_FILE", "")
    assert config._resolve_env_file() is None
    monkeypatch.setenv("HYBRIDSEC_ENV_FILE", "   ")
    assert config._resolve_env_file() is None
    monkeypatch.setenv("HYBRIDSEC_ENV_FILE", str(tmp_path / "custom.env"))
    assert config._resolve_env_file() == tmp_path / "custom.env"


# --- config: limits -------------------------------------------------------------------------------

def test_max_top_ports_is_clamped_to_nmaps_port_range(env_file):
    """Values outside 1..65535 are clamped and unreadable values fall back to the default, so a typo never breaks runs."""
    cases = [("-5", 1), ("70000", 65535), ("65535", 65535), ("  12 ", 12), ("+7", 7),
             ("abc", 1000), ("1e3", 1000), ("0x10", 1000)]
    for raw, expected in cases:
        assert reload_from(env_file, f"HYBRIDSEC_MAX_TOP_PORTS={raw}\n").max_top_ports == expected, raw


def test_timeout_limits_are_clamped_and_kept_consistent(env_file):
    """The maximum is at least 10 s, the default is at least 10 s and never above the maximum; typos use the defaults."""
    assert reload_from(env_file, "HYBRIDSEC_MAX_TIMEOUT=5\n").max_timeout_seconds == 10
    # The upper bound is the one requests accept (86400), so every advertised budget can be requested.
    raised = reload_from(env_file, "HYBRIDSEC_MAX_TIMEOUT=100000\nHYBRIDSEC_DEFAULT_TIMEOUT=90000\n")
    assert (raised.max_timeout_seconds, raised.default_timeout_seconds) == (86400, 86400)
    assert reload_from(env_file, "HYBRIDSEC_MAX_TIMEOUT=abc\n").max_timeout_seconds == 900
    lowered = reload_from(env_file, "HYBRIDSEC_MAX_TIMEOUT=60\n")  # the default of 180 is above this maximum
    assert (lowered.max_timeout_seconds, lowered.default_timeout_seconds) == (60, 60)
    assert reload_from(env_file, "HYBRIDSEC_MAX_TIMEOUT=60\nHYBRIDSEC_DEFAULT_TIMEOUT=5000\n").default_timeout_seconds == 60
    assert reload_from(env_file, "HYBRIDSEC_DEFAULT_TIMEOUT=3\n").default_timeout_seconds == 10
    assert reload_from(env_file, "HYBRIDSEC_DEFAULT_TIMEOUT=abc\n").default_timeout_seconds == 180


def test_concurrency_limit_and_ai_timeout_have_a_floor_of_one(env_file):
    """max_concurrent_runs and the AI timeout are at least 1; values that are not numbers use the defaults 3 and 120.
    The run cap is also kept at or below 20, the most the Settings API accepts, so the value shown can be saved."""
    for raw, expected in [("0", 1), ("-3", 1), ("abc", 3), ("2", 2), ("20", 20), ("100000", 20)]:
        assert reload_from(env_file, f"HYBRIDSEC_MAX_CONCURRENT_RUNS={raw}\n").max_concurrent_runs == expected, raw
    for raw, expected in [("-7", 1), ("x", 120), ("1", 1), ("45", 45)]:
        assert reload_from(env_file, f"HYBRIDSEC_AI_TIMEOUT={raw}\n").ai_timeout_seconds == expected, raw


# --- config: Host header allow-list ----------------------------------------------------------------

def test_allowed_hosts_are_lower_cased_trimmed_and_always_include_loopback(env_file):
    """Extra Host-header names are normalised and the loopback names can never be removed from the list."""
    loaded = reload_from(env_file, "HYBRIDSEC_ALLOWED_HOSTS=Hybridsec.LAB, 10.10.20.5 ,, hybridsec.lab:8000 ,  \n")
    # The Host check compares names without a port, so an entry written as "name:port" is stored as the name.
    assert loaded.allowed_hosts == LOOPBACK_HOSTS | {"hybridsec.lab", "10.10.20.5"}
    assert reload_from(env_file, "HYBRIDSEC_ALLOWED_HOSTS=\n").allowed_hosts == LOOPBACK_HOSTS


def test_bind_address_joins_allowed_hosts_unless_it_is_a_wildcard(env_file):
    """The address the server binds to is a valid Host name, except 0.0.0.0 and :: which mean "every interface"."""
    named = reload_from(env_file, "HYBRIDSEC_HOST=Hybridsec.Lab\n")
    assert named.host == "Hybridsec.Lab" and "hybridsec.lab" in named.allowed_hosts
    for wildcard in ("0.0.0.0", "::"):
        loaded = reload_from(env_file, f"HYBRIDSEC_HOST={wildcard}\n")
        assert loaded.host == wildcard and loaded.allowed_hosts == LOOPBACK_HOSTS


def test_allow_simulation_accepts_the_usual_boolean_spellings(env_file):
    """1/true/yes/on in any case mean true, any other word means false, and a blank value keeps the default (true)."""
    for raw in ("1", "true", "YES", "On", " TRUE "):
        assert reload_from(env_file, f"HYBRIDSEC_ALLOW_SIMULATION={raw}\n").allow_simulation is True, raw
    for raw in ("0", "false", "no", "off", "maybe"):
        assert reload_from(env_file, f"HYBRIDSEC_ALLOW_SIMULATION={raw}\n").allow_simulation is False, raw
    assert reload_from(env_file, "HYBRIDSEC_ALLOW_SIMULATION=\n").allow_simulation is True


# --- config: AI provider --------------------------------------------------------------------------

def test_explicit_provider_choice_wins_even_without_a_key(env_file, no_stored_credentials):
    """anthropic, openai or rules is used exactly as configured, together with that provider's (trimmed) model name."""
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=rules\n")
    assert (loaded.resolved_ai_provider(), loaded.ai_model()) == ("rules", None)
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=anthropic\n")
    assert (loaded.resolved_ai_provider(), loaded.ai_model()) == ("anthropic", "claude-opus-5-5")
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=openai\nOPENAI_MODEL= my-model \n")
    assert (loaded.resolved_ai_provider(), loaded.ai_model()) == ("openai", "my-model")
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=  ANTHROPIC \nANTHROPIC_MODEL= claude-test-model \n")
    assert (loaded.ai_provider, loaded.ai_model()) == ("anthropic", "claude-test-model")


def test_auto_provider_picks_the_first_provider_with_credentials(env_file, no_stored_credentials, monkeypatch):
    """auto (or any unknown value) chooses Anthropic, then OpenAI, then the rules planner, depending on the keys present."""
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=auto\n")
    assert (loaded.resolved_ai_provider(), loaded.ai_model()) == ("rules", None)
    assert reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=gemini\n").resolved_ai_provider() == "rules"
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy-not-a-real-key")  # a dummy, kept out of every file
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=auto\n")
    assert (loaded.resolved_ai_provider(), loaded.ai_model()) == ("openai", "gpt-4o-mini")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-dummy-not-a-real-key")
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=auto\n")
    assert (loaded.resolved_ai_provider(), loaded.ai_model()) == ("anthropic", "claude-opus-5-5")
    monkeypatch.delenv("HYBRIDSEC_AI_PROVIDER")  # the test environment forces "rules"; without it blank means auto
    assert reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=\n").ai_provider == "auto"


def test_anthropic_credentials_can_come_from_a_token_or_an_sdk_profile(env_file, no_stored_credentials, monkeypatch):
    """Besides a key, an ANTHROPIC_AUTH_TOKEN or a login profile the Anthropic SDK discovers lets "auto" choose
    Anthropic; an SDK error while looking is treated as "no profile"."""
    sdk = no_stored_credentials
    loaded = reload_from(env_file, "HYBRIDSEC_AI_PROVIDER=auto\n")
    assert loaded.anthropic_credentials_present() is False and loaded.resolved_ai_provider() == "rules"
    monkeypatch.setattr(sdk, "_has_active_profile_config", lambda: True)
    assert loaded.anthropic_credentials_present() is True and loaded.resolved_ai_provider() == "anthropic"
    monkeypatch.setattr(sdk, "_has_active_profile_config", lambda: False)
    monkeypatch.setattr(sdk, "_has_auto_discoverable_credentials", lambda: True)
    assert loaded.resolved_ai_provider() == "anthropic"

    def unreadable_profile_folder():
        raise OSError("profile folder unreadable")

    monkeypatch.setattr(sdk, "_has_auto_discoverable_credentials", unreadable_profile_folder)
    assert loaded.anthropic_credentials_present() is False and loaded.resolved_ai_provider() == "rules"
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "test-token-dummy")
    assert loaded.resolved_ai_provider() == "anthropic"


def test_unreadable_env_file_is_retried_and_then_the_last_good_values_stay(env_file, monkeypatch):
    """Windows locks .env for a moment while the Settings page replaces it: a failed read is retried, and if it
    keeps failing the values read last time stay in force instead of a request crashing."""
    assert reload_from(env_file, "HYBRIDSEC_MAX_TOP_PORTS=321\n").max_top_ports == 321
    real_dotenv_values = config.dotenv_values
    attempts: list[Path] = []

    def locked_twice(path):
        attempts.append(path)
        if len(attempts) <= 2:
            raise PermissionError(5, "Access is denied", str(path))
        return real_dotenv_values(path)

    monkeypatch.setattr(config, "dotenv_values", locked_twice)
    monkeypatch.setattr(config.time, "sleep", lambda seconds: None)
    env_file.write_text("HYBRIDSEC_MAX_TOP_PORTS=654\n", encoding="utf-8", newline="\n")
    assert settings.reload().max_top_ports == 654 and len(attempts) == 3  # two failures, then the new value

    def always_locked(path):
        raise PermissionError(5, "Access is denied", str(path))

    monkeypatch.setattr(config, "dotenv_values", always_locked)
    env_file.write_text("HYBRIDSEC_MAX_TOP_PORTS=999\n", encoding="utf-8", newline="\n")
    assert settings.reload().max_top_ports == 654  # the previous values are kept, the new file is not half-applied


def test_shell_bind_address_stays_an_accepted_host_when_the_env_file_overrides_it(env_file, monkeypatch):
    """run.sh/run.ps1 export HYBRIDSEC_HOST; .env may still say 127.0.0.1, but the address actually bound must pass
    the Host check, while a wildcard bind address is never a name."""
    monkeypatch.setenv("HYBRIDSEC_HOST", "10.10.20.9")
    loaded = reload_from(env_file, "HYBRIDSEC_HOST=127.0.0.1\n")
    assert loaded.host == "127.0.0.1"  # the file value wins for the setting itself
    assert "10.10.20.9" in loaded.allowed_hosts  # the shell's address is still an accepted Host header
    monkeypatch.setenv("HYBRIDSEC_HOST", "0.0.0.0")
    assert "0.0.0.0" not in reload_from(env_file, "HYBRIDSEC_HOST=127.0.0.1\n").allowed_hosts


# --- config: object identity ----------------------------------------------------------------------

def test_data_directory_is_fixed_after_the_first_load(env_file, monkeypatch, tmp_path):
    """Changing HYBRIDSEC_DATA_DIR while the server runs is ignored: the database must not move under live queries."""
    before = settings.data_dir
    elsewhere = tmp_path / "elsewhere"
    monkeypatch.setenv("HYBRIDSEC_DATA_DIR", str(elsewhere))
    assert reload_from(env_file, "").data_dir == before
    assert not elsewhere.exists()


def test_reload_returns_the_shared_settings_object_and_trims_text_values(env_file):
    """reload() returns the one object every module imported; model and URL values lose surrounding whitespace."""
    loaded = reload_from(env_file, "OPENAI_BASE_URL= https://llm.lab.example.edu/v1 \nANTHROPIC_MODEL=   \n")
    assert loaded is settings and loaded is config.settings
    assert loaded.openai_base_url == "https://llm.lab.example.edu/v1"
    assert loaded.anthropic_model == "claude-opus-5-5"  # blank falls back to the default
    assert reload_from(env_file, "").openai_base_url == "https://api.openai.com/v1"
    # The Custom tools allow-list keeps its entries as written (a path entry pins that file, and on Linux a path's
    # case matters) and loses blank items, like the other lists; the rules compare names in lower case themselves.
    assert reload_from(env_file, "HYBRIDSEC_CUSTOM_PROGRAMS= Curl, ,DIG \n").custom_programs == ["Curl", "DIG"]


# --- envfile: values ------------------------------------------------------------------------------

def test_validate_value_rejects_control_characters_and_names_the_setting():
    """NUL, bell, DEL, tab and carriage return could hide or inject text, so they are refused with the setting's name."""
    for bad in ("\x00", "a\x07b", "\x7f", "tab\there", "cr\rlf", "\x1f",
                "a\u2028b", "a\u2029b", "a\x85b"):  # Unicode line separators would split a value into two lines
        with pytest.raises(EnvValueError, match="ANTHROPIC_MODEL must not contain line breaks or control characters"):
            validate_value(bad, "ANTHROPIC_MODEL")
    with pytest.raises(EnvValueError, match="ANTHROPIC_MODEL must not contain single quotes"):
        validate_value("it's", "ANTHROPIC_MODEL")


def test_validate_value_accepts_printable_text_unchanged():
    """Spaces, #, double quotes, $, =, backticks, backslashes and non-ASCII letters are all storable as they are."""
    for value in ("abc", "with spaces", "#hash", 'say "hi"', "$HOME", "a=b", "", "ünïcödé ☃", "back\\slash",
                  "tick`", " padded ", "10.10.20.0/24,*.lab.example.edu"):
        assert validate_value(value) == value


def test_format_value_quotes_only_values_that_need_it():
    """Plain values are written bare; whitespace, #, quotes, $, backticks, backslashes and = get single quotes."""
    for plain in ("plain", "sk-ant-abc_123", "https://api.openai.com/v1", "10.10.20.0/24,*.lab.example.edu",
                  "a:b;c@d%e!f?g*h"):
        assert format_value(plain) == plain
    for special in ("with spaces", "#hash", 'say "hi"', "$HOME", "a=b", "tick`", "back\\slash", " padded "):
        assert format_value(special) == f"'{special}'"
    assert format_value("") == ""


def test_written_values_read_back_identically_through_python_dotenv(tmp_path):
    """Whatever quoting the writer chose, python-dotenv (which config.py uses) returns the original text."""
    values = {"A": "with spaces", "B": "#not a comment", "C": 'double "quotes"', "D": "$HOME stays literal",
              "E": "a=b=c", "F": "back\\slash", "G": "ünï ☃", "H": "trailing space ", "I": " leading",
              "J": "tick`", "K": "10.10.20.0/24,*.lab.example.edu", "L": "", "M": "x # y", "N": "a\\nb"}
    env = tmp_path / "roundtrip.env"
    update_env_file(env, values)
    assert dict(dotenv_values(env)) == values


# --- envfile: file structure ----------------------------------------------------------------------

def test_update_rewrites_keys_in_place_and_preserves_everything_else(tmp_path):
    """Comments, blank lines, ordering and unrelated keys are untouched; None clears a key to KEY=."""
    env = tmp_path / "keep.env"
    env.write_text("# c1\n\nA=1\n# c2\nB=2\n\nC=3\n", encoding="utf-8", newline="\n")
    update_env_file(env, {"B": "22", "A": None})
    assert env.read_text(encoding="utf-8") == "# c1\n\nA=\n# c2\nB=22\n\nC=3\n"


def test_update_recognises_export_and_spaced_assignments(tmp_path):
    """"export KEY=value" and "KEY = value" lines are the same key: rewritten once, never appended a second time."""
    env = tmp_path / "forms.env"
    env.write_text("export B=2\nC = 3\n", encoding="utf-8", newline="\n")
    update_env_file(env, {"B": "22", "C": "33"})
    text = env.read_text(encoding="utf-8")
    assert dict(dotenv_values(env)) == {"B": "22", "C": "33"}
    assert sum(line.startswith(("B=", "export B=")) for line in text.splitlines()) == 1
    assert _ADDED_KEYS_HEADER not in text  # nothing had to be appended


def test_update_distinguishes_similar_and_commented_out_keys(tmp_path, monkeypatch):
    """A is neither AB nor a, and "# A=1" is a comment: those lines stay as they are and A is appended. The file
    is read with python-dotenv's own parser, so text inside a quoted value, or a line python-dotenv cannot read,
    is never taken for a setting, and a save never changes any other setting."""
    env = tmp_path / "similar.env"
    env.write_text("AB=5\na=6\n# A=1\n", encoding="utf-8", newline="\n")
    update_env_file(env, {"A": "7"})
    text = env.read_text(encoding="utf-8")
    assert text.startswith("AB=5\na=6\n# A=1\n") and text.endswith("A=7\n")
    assert dict(dotenv_values(env)) == {"AB": "5", "a": "6", "A": "7"}
    # A line inside a multi-line quoted value is text, like a comment, even when it looks like KEY=value: it is
    # left alone and the real key is appended, so the setting really applies. A rewritten key whose own old
    # value spanned several lines keeps those lines as comments: they were not settings, and nothing is lost.
    notes = tmp_path / "notes.env"
    notes.write_text('NOTES="line one\nHYBRIDSEC_MAX_TOP_PORTS=500\nline three"\nB=\'x\nB=y\'\nC=1\n'
                     'lab.notes="a\nHYBRIDSEC_MAX_TIMEOUT=60\nb"\n', encoding="utf-8", newline="\n")
    update_env_file(notes, {"HYBRIDSEC_MAX_TOP_PORTS": "100", "B": "2", "HYBRIDSEC_MAX_TIMEOUT": "300"})
    assert dict(dotenv_values(notes)) == {"NOTES": "line one\nHYBRIDSEC_MAX_TOP_PORTS=500\nline three", "B": "2",
                                          "C": "1", "lab.notes": "a\nHYBRIDSEC_MAX_TIMEOUT=60\nb",
                                          "HYBRIDSEC_MAX_TOP_PORTS": "100", "HYBRIDSEC_MAX_TIMEOUT": "300"}
    assert "\n# B=y'\n" in notes.read_text(encoding="utf-8")
    # A line python-dotenv cannot read (an unclosed quote) is ignored by it; a save of another key keeps every
    # line after it in force, and a save of that key itself replaces the broken line.
    for text, update, expected in (
        ('HYBRIDSEC_ALLOWED_TARGETS="10.10.20.0/24\nHYBRIDSEC_ALLOW_SIMULATION=false\nANTHROPIC_MODEL=m\n',
         {"OPENAI_MODEL": "gpt-4o"},
         {"HYBRIDSEC_ALLOW_SIMULATION": "false", "ANTHROPIC_MODEL": "m", "OPENAI_MODEL": "gpt-4o"}),
        ('HYBRIDSEC_ALLOWED_TARGETS="10.10.20.0/24\nX=1\n', {"HYBRIDSEC_ALLOWED_TARGETS": "10.10.20.0/24"},
         {"HYBRIDSEC_ALLOWED_TARGETS": "10.10.20.0/24", "X": "1"}),
        ('K="abc\\\\"\nZ=3\n', {"Z": "4"}, {"K": "abc\\", "Z": "4"}),
    ):
        broken = tmp_path / "broken.env"
        broken.write_text(text, encoding="utf-8", newline="\n")
        before = dict(dotenv_values(broken))
        update_env_file(broken, update)
        after = dict(dotenv_values(broken))
        assert after == expected, text
        assert {k: v for k, v in after.items() if k not in update} == {k: v for k, v in before.items() if k not in update}
    # The new content must read back with every other setting unchanged; if it would not, nothing is written.
    guarded = tmp_path / "guarded.env"
    guarded.write_text("A=1\nB=2\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(envfile, "_apply_updates", lambda text, updates: "A=9\nB=3\n")
    with pytest.raises(EnvValueError, match="Saving would also change A"):
        update_env_file(guarded, {"B": "3"})
    assert guarded.read_text(encoding="utf-8") == "A=1\nB=2\n"


def test_new_keys_are_appended_under_a_header_after_exactly_one_blank_line(tmp_path):
    """Appended keys go under one comment header; a blank line is added only when the file does not end with one."""
    env = tmp_path / "append.env"
    env.write_text("A=1", encoding="utf-8")  # no trailing newline
    update_env_file(env, {"B": "2"})
    assert env.read_text(encoding="utf-8") == f"A=1\n\n{_ADDED_KEYS_HEADER}\nB=2\n"
    env.write_text("A=1\n\n", encoding="utf-8", newline="\n")  # already ends with a blank line
    update_env_file(env, {"B": "2"})
    assert env.read_text(encoding="utf-8") == f"A=1\n\n{_ADDED_KEYS_HEADER}\nB=2\n"


def test_update_creates_a_missing_file_and_its_directories_without_leftovers(tmp_path):
    """A first save creates the file (and folders); the temporary file used for the atomic write is gone, also
    when the save fails because the file is read-only (on Windows os.replace cannot overwrite it): the temporary
    copy of the new contents, which may carry an API key, inherited the read-only bit and must still be removed."""
    env = tmp_path / "sub" / "dir" / "new.env"
    update_env_file(env, {"ONLY": "1"})
    assert env.read_text(encoding="utf-8") == f"{_ADDED_KEYS_HEADER}\nONLY=1\n"
    assert [p.name for p in env.parent.iterdir()] == ["new.env"]
    env.chmod(stat.S_IREAD)
    try:
        with contextlib.suppress(OSError):  # on Windows the read-only file cannot be replaced; elsewhere it can
            update_env_file(env, {"ONLY": "2", "SECRET": "sk-test-not-a-real-key"})
        assert [p.name for p in env.parent.iterdir()] == ["new.env"]
    finally:
        env.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_one_bad_value_in_a_batch_changes_nothing(tmp_path):
    """Every value is validated before anything is written, so a bad value leaves the file exactly as it was."""
    env = tmp_path / "batch.env"
    env.write_text("A=1\n", encoding="utf-8", newline="\n")
    with pytest.raises(EnvValueError, match="BAD"):
        update_env_file(env, {"A": "2", "GOOD": "ok", "BAD": "x\ny"})
    assert env.read_text(encoding="utf-8") == "A=1\n"
    assert [p.name for p in tmp_path.iterdir()] == ["batch.env"]


def test_windows_line_endings_and_a_bom_are_normalised_on_rewrite(tmp_path):
    """A file saved with CRLF and a BOM is rewritten as plain UTF-8 with LF line endings and nothing else changed."""
    env = tmp_path / "notepad.env"
    env.write_bytes(b"\xef\xbb\xbfA=1\r\nB=2\r\n")
    update_env_file(env, {"A": "x"})
    assert env.read_bytes() == b"A=x\nB=2\n"
    assert dict(dotenv_values(env)) == {"A": "x", "B": "2"}
    # With two marks the server reads the first key as "\ufeffA" (python-dotenv strips one), so it is not in
    # force; the writer sees the file the same way and keeps it so, instead of switching A on.
    env.write_bytes(b"\xef\xbb\xbf\xef\xbb\xbfA=1\nB=2\n")
    update_env_file(env, {"B": "3"})
    assert dict(dotenv_values(env)) == {"\ufeffA": "1", "B": "3"}
    # A rewritten line keeps its export prefix and the comment at its end; a # inside quotes is not a comment.
    env.write_text("export A=1   # keep low\nB=\"x # y\" # note\n", encoding="utf-8", newline="\n")
    update_env_file(env, {"A": "2", "B": "z"})
    assert env.read_text(encoding="utf-8") == "export A=2   # keep low\nB=z # note\n"


def test_only_real_line_breaks_split_the_file_on_rewrite(tmp_path):
    """Only \\n, \\r\\n and \\r end a line, as python-dotenv sees it: a U+2028 inside a comment stays on that line."""
    env = tmp_path / "separators.env"
    env.write_bytes("# note\u2028still the note\x85same line\nA=1\n".encode())
    update_env_file(env, {"A": "2"})
    assert env.read_text(encoding="utf-8") == "# note\u2028still the note\x85same line\nA=2\n"
    assert dict(dotenv_values(env)) == {"A": "2"}


def test_concurrent_updates_from_two_threads_lose_no_key(tmp_path):
    """Saves are serialised by a lock: two threads writing different keys at the same time both end up in the file."""
    env = tmp_path / "threads.env"
    env.write_text("BASE=1\n", encoding="utf-8", newline="\n")

    def writer(prefix: str) -> None:
        for i in range(15):
            update_env_file(env, {f"{prefix}_{i}": str(i)})

    threads = [threading.Thread(target=writer, args=(prefix,)) for prefix in ("LEFT", "RIGHT")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    values = dotenv_values(env)
    assert values["BASE"] == "1"
    assert all(values[f"{prefix}_{i}"] == str(i) for prefix in ("LEFT", "RIGHT") for i in range(15))
    assert env.read_text(encoding="utf-8").count(_ADDED_KEYS_HEADER) == 1


# --- storage --------------------------------------------------------------------------------------

STAMP = datetime(2099, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # far in the future: newest in the shared database


@pytest.fixture(scope="module")
def database():
    """The tables exist in the private test database (idempotent, exactly what the app does at startup)."""
    storage.init_db()


@pytest.fixture
def cleanup(database):
    """Collects the ids of the runs and plans a test creates and deletes them afterwards."""
    created: dict[str, list[str]] = {"runs": [], "plans": []}
    yield created
    for run_id in created["runs"]:
        storage.delete_run(run_id)
    if created["plans"]:
        with storage.connect() as conn:
            conn.executemany("DELETE FROM plans WHERE id = ?", [(plan_id,) for plan_id in created["plans"]])


def new_run(run_id: str, created_at: datetime = STAMP, **fields) -> Run:
    """A completed Nmap run on a lab address; every field can be overridden."""
    values = {"id": run_id, "target": "10.10.20.5", "status": "completed", "tools": ["nmap"], "created_at": created_at}
    values.update(fields)
    return Run(**values)


def new_plan(plan_id: str, created_at: datetime = STAMP, **fields) -> PlanResponse:
    """A minimal rules-planner revision; every field can be overridden."""
    values = dict(
        id=plan_id, provider="rules", created_at=created_at,
        request=PlanRequest(objective="Detailed storage test: plan a port scan of a lab host."),
        plan=Plan(summary="s", workflow=[PlanStep(order=1, tool="nmap", stage="port_scan", purpose="p")],
                  inputs=["i"], outputs=["o"], safety_controls=SafetyControls()),
        tools_available={"nmap": False},
    )
    values.update(fields)
    return PlanResponse(**values)


def test_run_round_trip_preserves_unicode_nested_data_and_timestamps(cleanup):
    """A run comes back from SQLite exactly as saved: Unicode text, nested JSON in technologies, time zone and all."""
    run = new_run("dtlrt0000001", label="Läb ☃ — \u202eevil\u202c",
                  created_at=datetime(2031, 5, 6, 7, 8, 9, 123456, tzinfo=timezone.utc),
                  stages=[StageResult(stage="port_scan", tool="nmap", status="completed")],
                  ports=[PortFinding(host="h (10.10.20.5)", port=22)],
                  web=[WebFinding(url="http://10.10.20.5", host="10.10.20.5", port=80,
                                  technologies=[{"name": "x", "tags": ["a", {"b": [1, 2.5, None, True]}]}])],
                  vulns=[VulnFinding(url="http://10.10.20.5/ünï", description="日本語 ✓ \U0001f512")],
                  summary=RunSummary(risk_score=42, highlights=["h1"]), log=["l1"])
    cleanup["runs"].append(run.id)
    storage.save_run(run)
    stored = storage.get_run(run.id)
    assert stored == run
    assert stored.created_at == run.created_at and stored.created_at.tzinfo is not None
    assert stored.web[0].technologies[0]["tags"][1]["b"] == [1, 2.5, None, True]


def test_unknown_run_or_plan_id_returns_none(database):
    """Looking up an id that was never stored gives None rather than an error, which the API turns into 404."""
    assert storage.get_run("dtl-no-such-run") is None and storage.get_run("") is None
    assert storage.get_plan("dtl-no-such-plan") is None and storage.get_plan("") is None
    # An id SQLite cannot be given (a lone surrogate, which JSON allows as \ud800) is unknown as well, not an
    # encoding error that would reach the client as a 500 (issue 3 of the 12 November test round).
    for odd in ("\ud800", "dtl\udfffrun"):
        assert storage.get_run(odd) is None and storage.get_plan(odd) is None
        assert storage.delete_run(odd) is False and storage.delete_custom_tool(odd) is False


def test_delete_run_reports_whether_a_run_existed(cleanup):
    """Deleting returns True once, then the run is gone from lookups and the history, and False the second time."""
    run = new_run("dtldel000001")
    cleanup["runs"].append(run.id)
    storage.save_run(run)
    assert storage.delete_run(run.id) is True
    assert storage.get_run(run.id) is None
    assert all(item.id != run.id for item in storage.list_runs())
    assert storage.delete_run(run.id) is False


def test_list_runs_is_newest_first_and_honours_the_limit(cleanup):
    """The history is ordered by creation time, newest first, regardless of the order the runs were saved in."""
    ids = ["dtlord000001", "dtlord000002", "dtlord000003"]
    stamps = [STAMP, STAMP + timedelta(days=2), STAMP + timedelta(days=1)]
    for run_id, stamp in zip(ids, stamps, strict=True):
        cleanup["runs"].append(run_id)
        storage.save_run(new_run(run_id, created_at=stamp))
    assert [item.id for item in storage.list_runs() if item.id in ids] == ["dtlord000002", "dtlord000003", "dtlord000001"]
    assert [item.id for item in storage.list_runs(limit=1)] == ["dtlord000002"]  # the newest run in the database
    assert len(storage.list_runs(limit=2)) == 2


def test_list_runs_shows_the_latest_saved_state_without_the_findings(cleanup):
    """Saving again overwrites the run; the history item carries label, mode, tools, summary and duration only."""
    run = new_run("dtlupd000001", status="running", label="first", mode="simulated", tools=["nmap", "whatweb"],
                  vulns=[VulnFinding(url="http://10.10.20.5", description="x")])
    cleanup["runs"].append(run.id)
    storage.save_run(run)
    run.status, run.duration_seconds, run.summary = "completed", 12.5, RunSummary(open_ports=3, risk_score=40)
    storage.save_run(run)
    item = next(i for i in storage.list_runs() if i.id == run.id)
    assert (item.status, item.label, item.mode, item.tools, item.duration_seconds) == (
        "completed", "first", "simulated", ["nmap", "whatweb"], 12.5)
    assert item.summary.open_ports == 3 and item.summary.risk_score == 40
    assert not hasattr(item, "vulns")
    assert storage.to_list_item(storage.get_run(run.id)) == item


def test_list_runs_tolerates_documents_saved_by_older_versions(cleanup):
    """A stored document without the newer fields (mode, tools, summary, label, duration) still appears in the history."""
    old = {"id": "dtlold000001", "target": "10.10.20.5", "status": "completed", "created_at": STAMP.isoformat()}
    cleanup["runs"].append(old["id"])
    with storage.connect() as conn:
        conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) VALUES (?, ?, ?, ?, ?)",
                     (old["id"], old["created_at"], old["target"], old["status"], json.dumps(old)))
    item = next(i for i in storage.list_runs() if i.id == old["id"])
    assert (item.mode, item.tools, item.label, item.duration_seconds) == ("live", [], None, None)
    assert item.summary == RunSummary()
    # A finding with a null severity loads as info, so the run, its reports and the comparison still open; a status
    # outside the model is listed but says it cannot be read when opened (the history reads the raw JSON).
    for doc_id, extra in (("dtlold000002", {"tools": ["nikto"], "vulns": [{"url": "http://10.10.20.5",
                                                                           "severity": None, "reference": None,
                                                                           "description": "x"}]}),
                          ("dtlold000003", {"status": "cancelled"})):
        cleanup["runs"].append(doc_id)
        document = {**old, "id": doc_id, **extra}
        with storage.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) VALUES (?, ?, ?, ?, ?)",
                         (doc_id, old["created_at"], old["target"], document["status"], json.dumps(document)))
    assert {"dtlold000002", "dtlold000003"} <= {i.id for i in storage.list_runs()}
    assert [(v.severity, v.reference) for v in storage.get_run("dtlold000002").vulns] == [("info", "")]
    with pytest.raises(storage.DocumentUnreadable, match="It can still be deleted"):
        storage.get_run("dtlold000003")
    # A document that is JSON but not an object (null, a list, a number, a string) is listed as unreadable, so one
    # such row never takes the whole history down (issue 10); it is counted the same way and can be deleted.
    shapes = {"dtlold000004": "null", "dtlold000005": "[1, 2]", "dtlold000006": "42", "dtlold000007": '"text"'}
    unreadable_before = storage.count_runs().get("unreadable", 0)
    with storage.connect() as conn:
        for doc_id, document in shapes.items():
            cleanup["runs"].append(doc_id)
            conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) "
                         "VALUES (?, ?, ?, ?, ?)", (doc_id, old["created_at"], old["target"], "completed", document))
    listed = {i.id: i for i in storage.list_runs(limit=1000)}
    assert [(listed[doc_id].status, listed[doc_id].target) for doc_id in shapes] == [("unreadable", "10.10.20.5")] * 4
    assert storage.count_runs().get("unreadable", 0) == unreadable_before + 4
    for doc_id in shapes:
        with pytest.raises(storage.DocumentUnreadable, match="It can still be deleted"):
            storage.get_run(doc_id)
    assert all(storage.delete_run(doc_id) for doc_id in shapes)
    # A stored custom tool that no longer reads (damaged, or written by another version) or that holds a tool with
    # another name than its row is listed by its row name as unreadable instead of being hidden: it still counts
    # towards the limit and holds its name, so it must be visible and deletable by that name (issue 21).
    tool = CustomTool(name="dtlother", program="curl", args=["-sI", "{url}"], scope="url", created_at=STAMP)
    rows = {"dtlctbroken1": "{", "dtlctbroken2": "[]", "dtlctbroken3": json.dumps({"name": "dtlctbroken3"}),
            "dtlctrowname": tool.model_dump_json()}
    try:
        with storage.connect() as conn:
            for name, document in rows.items():
                conn.execute("INSERT INTO custom_tools (name, created_at, document) VALUES (?, ?, ?)",
                             (name, STAMP.isoformat(), document))
        tools, unreadable = storage.custom_tool_rows()
        assert [name for name in unreadable if name in rows] == sorted(rows)  # by row name, in name order
        assert not {t.name for t in tools} & {*rows, "dtlother"}
        assert storage.list_custom_tools() == tools and storage.unreadable_custom_tools() == unreadable
        assert storage.add_custom_tool(tool.model_copy(update={"name": "dtlctbroken1"}), limit=100) == "exists"
        assert storage.add_custom_tool(tool, limit=len(tools) + len(unreadable)) == "full"
        # A row whose name no request can carry (NULL, a blob, . or ..) is in neither list, since nothing could
        # delete it, and the limit does not count it either.
        with storage.connect() as conn:
            for value in (None, b"\x00\xff", ".", ".."):
                conn.execute("INSERT INTO custom_tools (name, created_at, document) VALUES (?, ?, ?)",
                             (value, STAMP.isoformat(), tool.model_dump_json()))
        assert storage.custom_tool_rows() == (tools, unreadable)
        assert storage.add_custom_tool(tool, limit=len(tools) + len(unreadable) + 1) == "added"
        assert storage.delete_custom_tool("dtlother")
        assert all(storage.delete_custom_tool(name) for name in rows)
        assert not set(rows) & set(storage.unreadable_custom_tools())
        assert storage.delete_custom_tool("dtlctrowname") is False
    finally:
        for name in (*rows, "dtlother"):
            storage.delete_custom_tool(name)
        with storage.connect() as conn:
            conn.execute("DELETE FROM custom_tools WHERE typeof(name) != 'text' OR name IN ('.', '..')")


def test_plan_round_trip_and_overwrite_by_id(cleanup):
    """A plan revision is stored as saved; saving the same id again replaces it instead of adding a copy."""
    plan = new_plan("dtlplan00001")
    cleanup["plans"].append(plan.id)
    storage.save_plan(plan)
    assert storage.get_plan(plan.id) == plan
    storage.save_plan(plan.model_copy(update={"note": "kept the previous revision"}))
    assert storage.get_plan(plan.id).note == "kept the previous revision"
    assert sum(stored.id == plan.id for stored in storage.list_plans()) == 1


def test_list_plans_is_newest_first_and_honours_the_limit(cleanup):
    """Plan revisions are listed by creation time, newest first."""
    ids = ["dtlplan00011", "dtlplan00012", "dtlplan00013"]
    stamps = [STAMP + timedelta(days=1), STAMP + timedelta(days=3), STAMP + timedelta(days=2)]
    for plan_id, stamp in zip(ids, stamps, strict=True):
        cleanup["plans"].append(plan_id)
        storage.save_plan(new_plan(plan_id, created_at=stamp))
    assert [p.id for p in storage.list_plans() if p.id in ids] == ["dtlplan00012", "dtlplan00013", "dtlplan00011"]
    assert [p.id for p in storage.list_plans(limit=1)] == ["dtlplan00012"]
    # A damaged plan document is left out of the list instead of failing it, and fetching it says it is unreadable.
    damaged = json.loads(new_plan("dtlplan00019").model_dump_json())
    del damaged["tools_available"]
    cleanup["plans"].append("dtlplan00019")
    with storage.connect() as conn:
        conn.execute("INSERT OR REPLACE INTO plans (id, created_at, document) VALUES (?, ?, ?)",
                     ("dtlplan00019", (STAMP + timedelta(days=4)).isoformat(), json.dumps(damaged)))
    assert [p.id for p in storage.list_plans() if p.id in ids] == ["dtlplan00012", "dtlplan00013", "dtlplan00011"]
    with pytest.raises(storage.DocumentUnreadable, match="stored plan 'dtlplan00019' cannot be read"):
        storage.get_plan("dtlplan00019")


def test_fail_stale_runs_fails_queued_runs_and_only_their_unfinished_stages(cleanup):
    """A run that never started is failed with the reason; finished stages keep their status, pending ones fail."""
    queued = new_run("dtlstale0001", status="queued", tools=["nmap", "whatweb"],
                     stages=[StageResult(stage="port_scan", tool="nmap", status="completed"),
                             StageResult(stage="web_fingerprint", tool="whatweb")])
    cleanup["runs"].append(queued.id)
    storage.save_run(queued)
    assert storage.fail_stale_runs(reason="Detailed test restart.") >= 1
    stored = storage.get_run(queued.id)
    assert stored.status == "failed" and stored.error == "Detailed test restart."
    assert stored.finished_at is not None and stored.duration_seconds is None  # it never started: no duration
    assert [s.status for s in stored.stages] == ["completed", "failed"]
    assert [s.error for s in stored.stages] == [None, "Detailed test restart."]
    assert stored.log[-1].endswith("Detailed test restart.")
    assert next(i for i in storage.list_runs() if i.id == queued.id).status == "failed"
    # Startup recovery must not stop at a damaged document (the server would never start): one that does not load
    # has only its status changed, one that is not JSON keeps its text, and a naive start time counts as UTC.
    naive = new_run("dtlstale0006", status="running", started_at=datetime(2020, 1, 1, 12, 0, 0)).model_dump_json()
    rows = {"dtlstale0004": json.dumps({**json.loads(new_run("dtlstale0004", status="running").model_dump_json()),
                                        "stages": [{"stage": "port_scan", "tool": "nmap", "status": "interrupted"}]}),
            "dtlstale0005": "not json at all",
            "dtlstale0006": naive}
    with storage.connect() as conn:
        for doc_id, document in rows.items():
            cleanup["runs"].append(doc_id)
            conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) VALUES (?, ?, ?, ?, ?)",
                         (doc_id, STAMP.isoformat(), "10.10.20.5", "running", document))
    assert storage.fail_stale_runs(reason="Detailed test restart.") == 3
    listed = {i.id: i.status for i in storage.list_runs()}
    # A document that is not even JSON stays in the history as "unreadable", so it can be found and deleted.
    assert listed["dtlstale0004"] == "failed" and listed["dtlstale0005"] == "unreadable"
    with storage.connect() as conn:
        assert conn.execute("SELECT status FROM runs WHERE id = 'dtlstale0005'").fetchone() == ("failed",)
    recovered = storage.get_run("dtlstale0006")
    assert recovered.status == "failed" and recovered.duration_seconds > 0
    # Text that is not UTF-8, a document too deeply nested to write back, a document that still says running
    # while its row does not, a bad creation time, and an id the API cannot address: startup recovery never
    # fails, every addressable run is listed and deletable, and the counts agree with the list.
    deep = '{"id": "dtlstale0008", "status": "running", "x": ' + "[" * 10000 + "]" * 10000 + "}"
    with storage.connect() as conn:
        rows = [("dtlstale0007", STAMP.isoformat(), "running", None),
                ("dtlstale0008", STAMP.isoformat(), "running", deep),
                ("dtlstale0009", STAMP.isoformat(), "completed", new_run("dtlstale0009", status="running").model_dump_json()),
                ("dtlstale0010", "not a date", "completed", "{"),
                ("dtl/stale011", STAMP.isoformat(), "completed", "{")]
        for doc_id, created, status, document in rows:
            cleanup["runs"].append(doc_id)
            if document is None:  # bytes that are not UTF-8, stored as text
                conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) "
                             "VALUES (?, ?, '10.10.20.5', ?, CAST(X'7B226964223A2262616480FF227D' AS TEXT))",
                             (doc_id, created, status))
            else:
                conn.execute("INSERT OR REPLACE INTO runs (id, created_at, target, status, document) VALUES (?, ?, ?, ?, ?)",
                             (doc_id, created, "10.10.20.5", status, document))
    storage.fail_stale_runs(reason="Detailed test restart.")
    listed = {i.id: i.status for i in storage.list_runs(limit=1000)}
    # The deep document is either read (then shown failed, from its row) or not (unreadable): never "running".
    assert listed["dtlstale0007"] == "unreadable" and listed["dtlstale0008"] in ("failed", "unreadable")
    assert listed["dtlstale0009"] == "failed" and storage.get_run("dtlstale0009").status == "failed"
    assert listed["dtlstale0010"] == "unreadable" and "dtl/stale011" not in listed
    counts = storage.count_runs()
    assert sum(counts.values()) == len(listed)  # the total the dashboard shows is the number of runs it lists
    assert storage.delete_run("dtlstale0007") and storage.delete_run("dtlstale0010")


def test_fail_stale_runs_leaves_finished_runs_alone(cleanup):
    """Completed and failed runs are not touched by the startup recovery, and a clean database reports zero."""
    done = new_run("dtlstale0002", status="completed")
    failed = new_run("dtlstale0003", status="failed", error="original reason")
    for run in (done, failed):
        cleanup["runs"].append(run.id)
        storage.save_run(run)
    storage.fail_stale_runs()
    assert storage.get_run(done.id) == done and storage.get_run(failed.id) == failed
    assert storage.fail_stale_runs() == 0


def test_parallel_saves_from_worker_threads_are_all_stored(cleanup):
    """The process-wide lock serialises writers: runs saved from several threads at once are all retrievable."""
    ids = [f"dtlpar{i:06d}" for i in range(20)]
    cleanup["runs"].extend(ids)

    def save(chunk: list[str]) -> None:
        for run_id in chunk:
            storage.save_run(new_run(run_id, label=run_id))

    threads = [threading.Thread(target=save, args=(ids[i::4],)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(storage.get_run(run_id).label == run_id for run_id in ids)
