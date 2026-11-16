"""Regression tests for the defects found by the independent reviews and the report author.

Each test names the behaviour it protects. They run offline like the rest of the suite and reuse the
environment that tests/test_api.py sets up (a private .env and data directory).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import tests.test_api  # noqa: F401  (importing it points the app at a private .env and data directory)
from app.main import app
from app.routers.settings_api import require_local


@pytest.fixture(scope="module")
def client():
    # The TestClient's peer is "testclient", not a loopback IP, so the settings guard is overridden here.
    app.dependency_overrides[require_local] = lambda: None
    with TestClient(app, base_url="http://localhost") as c:
        yield c
    app.dependency_overrides.clear()


def test_planner_falls_back_to_rules_when_provider_fails(client, monkeypatch):
    """A provider error never blocks planning: the rules engine answers and the note explains why."""
    from app import planner

    def boom(provider, prompt):
        raise RuntimeError("simulated provider outage")

    monkeypatch.setattr(planner, "_call_provider", boom)
    client.put("/api/settings", json={"ai_provider": "anthropic"})
    try:
        resp = client.post("/api/ai/plan", json={"tools": ["nmap", "whatweb"],
                                                 "objective": "Fallback test: plan a hybrid scan of a lab host."})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["provider"] == "rules" and body["model"] is None
        assert "anthropic planner failed" in body["note"] and "rules planner" in body["note"]
        assert [s["tool"] for s in body["plan"]["workflow"]] == ["nmap", "whatweb"]
        # The Settings page's Test planner reports that fallback as a failure, with the same explanation.
        tested = client.post("/api/settings/test-planner").json()
        assert tested["ok"] is False and tested["provider"] == "rules" and tested["model"] is None
        assert "anthropic planner failed" in tested["note"]
    finally:
        client.put("/api/settings", json={"ai_provider": "rules"})


def test_planner_command_templates_match_the_executor():
    """The plan describes the real commands, including WhatWeb's same-site redirect limit."""
    from app.planner import EXECUTOR_COMMANDS
    assert "--follow-redirect=same-site" in EXECUTOR_COMMANDS["whatweb"]
    assert "--host-timeout" in EXECUTOR_COMMANDS["nmap"] and "-maxtime" in EXECUTOR_COMMANDS["nikto"]


def test_compare_keeps_http_and_https_findings_apart():
    """The same Nikto message on http and on https are two findings, not one."""
    from app.compare import compare_runs
    from app.schemas import Run, VulnFinding
    now = datetime.now(timezone.utc)
    base = Run(id="scheme000001", target="h", status="completed", tools=["nikto"], created_at=now)
    other = Run(id="scheme000002", target="h", status="completed", tools=["nikto"], created_at=now,
                vulns=[VulnFinding(url="http://h/", severity="low", description="X-Frame-Options missing"),
                       VulnFinding(url="https://h/", severity="low", description="X-Frame-Options missing")])
    assert len(compare_runs(base, other).vulns_added) == 2


def test_highlights_put_severe_findings_before_version_notes():
    """The eight-item cap must never hide a high finding behind version disclosures."""
    from app.hybrid import summarize
    from app.schemas import Run, VulnFinding, WebFinding
    techs = [{"name": name, "version": "1.0"} for name in ("nginx", "PHP", "jQuery", "WordPress", "Apache",
                                                             "Tomcat", "Jetty", "Drupal", "Joomla")]
    run = Run(id="hl0000000001", target="10.0.0.9", status="completed", tools=["whatweb", "nikto"],
              created_at=datetime.now(timezone.utc),
              web=[WebFinding(url="http://10.0.0.9", host="10.0.0.9", port=80, status_code=200, technologies=techs)],
              vulns=[VulnFinding(url="http://10.0.0.9/manager/html", severity="high",
                                 description="Tomcat Manager application is reachable.")])
    highlights = summarize(run).highlights
    assert highlights[0].startswith("[high]") and len(highlights) <= 8


def test_short_budget_still_gives_nikto_a_usable_share():
    """With three tools and a 60 s budget Nikto gets its 20 s minimum instead of an unusable 15 s."""
    from app.hybrid import MIN_NIKTO_SECONDS, _stage_budgets
    shares = _stage_budgets(["nmap", "whatweb", "nikto"], 60)
    assert shares["nikto"] >= MIN_NIKTO_SECONDS
    assert shares["nmap"] >= 10 and shares["whatweb"] >= 10
    assert sum(shares.values()) <= 60 + 1e-6


def test_probe_urls_use_the_operator_hostname():
    """A hostname target is probed by name so virtual hosts answer for the intended site."""
    from app.hybrid import _probe_host
    from app.schemas import PortFinding, Run
    from app.tools.parsers import url_for
    now = datetime.now(timezone.utc)
    port = PortFinding(host="203.0.113.10", port=443, service="ssl/http", is_web=True)
    named = Run(id="vh0000000001", target="shop.example.com", status="running", tools=["nmap"], created_at=now)
    numeric = Run(id="vh0000000002", target="203.0.113.10", status="running", tools=["nmap"], created_at=now)
    assert url_for(port, _probe_host(named)) == "https://shop.example.com"
    assert url_for(port, _probe_host(numeric)) == "https://203.0.113.10"


def test_csv_export_states_the_run_mode():
    """Every CSV row carries live/simulated so an exported sheet cannot be mistaken for real data."""
    from app.reports import render_csv
    from app.schemas import PortFinding, Run
    run = Run(id="csvmode00001", target="10.0.0.5", status="completed", mode="simulated", tools=["nmap"],
              created_at=datetime.now(timezone.utc),
              ports=[PortFinding(host="10.0.0.5", port=22, service="ssh")])
    lines = render_csv(run).splitlines()
    assert lines[0].endswith(",mode") and lines[1].endswith(",simulated")


def test_origin_must_match_host_and_port(client):
    """Another local application on a different port is a different origin and is rejected."""
    body = {"tools": ["nmap"], "objective": "Origin test: plan a port scan of an authorized lab host."}
    same = client.post("/api/ai/plan", json=body, headers={"Host": "localhost:8000", "Origin": "http://localhost:8000"})
    other_port = client.post("/api/ai/plan", json=body,
                             headers={"Host": "localhost:8000", "Origin": "http://localhost:9999"})
    assert same.status_code == 200 and other_port.status_code == 403
