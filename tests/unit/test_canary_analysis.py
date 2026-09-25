"""The Argo Rollouts canary analysis (deploy/kind/analysistemplate.yaml)
asserts things about this app; these tests pin that contract so a route
change can't silently turn the analysis into a false pass or a stuck
rollout."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

TEMPLATE = Path(__file__).resolve().parents[2] / "deploy" / "kind" / "analysistemplate.yaml"


def _metrics():
    return {m["name"]: m for m in yaml.safe_load(TEMPLATE.read_text())["spec"]["metrics"]}


def test_analysis_declares_exactly_functional_and_security_control():
    assert set(_metrics()) == {"functional", "security-control"}


def test_functional_metric_path_serves_the_login_form(client):
    url = _metrics()["functional"]["provider"]["web"]["url"]
    r = client.get(url.split(".svc", 1)[1])
    assert r.status_code == 200  # the web provider errors on non-2xx
    assert 'name="password"' in r.text  # what successCondition looks for


def test_security_control_expectations_match_the_app(client):
    spec = _metrics()["security-control"]["provider"]["job"]["spec"]["template"]["spec"]
    script = spec["containers"][0]["args"][0]
    checks = re.findall(r"^\s*expect (GET|POST) +(\S+) (\d{3})(?: (\S+))?$", script, re.M)
    assert len(checks) >= 4
    for method, path, code, location in checks:
        r = client.request(method, path, follow_redirects=False)
        assert r.status_code == int(code), (method, path, r.status_code)
        if location:
            assert r.headers["location"] == location
