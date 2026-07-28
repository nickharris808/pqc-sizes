"""SARIF output for the window check.

A malformed SARIF file is not a loud failure: GitHub ignores it and the build goes
green having verified nothing. So this validates against the published schema, not
just against my own idea of the shape.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from pqc_sizes import max_concurrent_contexts, reassembly_window
from pqc_sizes.report import SARIF_SCHEMA, sarif_report

EXIT_OK, EXIT_FINDING, EXIT_USAGE = 0, 1, 2


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "pqc_sizes.cli", *args],
                          capture_output=True, text=True, timeout=60)


def report(obj, budget, conc):
    return sarif_report(reassembly_window(obj, budget, conc),
                        max_concurrent_contexts(obj, budget))


# ---------------------------------------------------------------------- structure

def test_empty_window_produces_exactly_one_error():
    log = report(12000, 32768, 3)
    results = log["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"
    assert "EMPTY WINDOW" in results[0]["message"]["text"]


def test_a_safe_window_produces_no_results():
    assert report(7533, 65536, 4)["runs"][0]["results"] == []


def test_result_references_a_declared_rule():
    log = report(12000, 32768, 3)
    declared = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in log["runs"][0]["results"]} <= declared


def test_finding_carries_the_actionable_numbers():
    props = report(12000, 32768, 3)["runs"][0]["results"][0]["properties"]
    assert props["ceiling"] == 10922
    assert props["max_safe_concurrency"] == 2


def test_no_finding_is_emitted_as_a_note():
    """An empty window has no advisory reading."""
    for result in report(12000, 32768, 3)["runs"][0]["results"]:
        assert result["level"] == "error"


# --------------------------------------------------------------- spec conformance

def test_declared_schema_url_resolves():
    import urllib.request
    try:
        with urllib.request.urlopen(SARIF_SCHEMA, timeout=20) as response:
            assert response.status == 200
            assert len(response.read()) > 10_000
    except OSError as exc:
        pytest.skip(f"network unavailable: {exc}")


@pytest.mark.parametrize("args", [(12000, 32768, 3), (7533, 65536, 4)])
def test_validates_against_the_official_schema(args):
    jsonschema = pytest.importorskip("jsonschema")
    import urllib.request
    try:
        with urllib.request.urlopen(SARIF_SCHEMA, timeout=20) as response:
            schema = json.loads(response.read())
    except OSError as exc:
        pytest.skip(f"network unavailable: {exc}")
    jsonschema.validate(report(*args), schema)


# --------------------------------------------------------------------- CLI wiring

def test_cli_sarif_keeps_the_exit_code(tmp_path):
    cfg = tmp_path / "pqc.json"
    cfg.write_text(json.dumps({"largest_object": 12000, "budget": 32768,
                               "concurrency": 3}))
    r = run("check", str(cfg), "--format", "sarif")
    assert r.returncode == EXIT_FINDING, "the format must not mask the verdict"
    assert json.loads(r.stdout)["version"] == "2.1.0"


def test_cli_sarif_points_at_the_config(tmp_path):
    cfg = tmp_path / "myconfig.json"
    cfg.write_text(json.dumps({"largest_object": 12000, "budget": 32768,
                               "concurrency": 3}))
    log = json.loads(run("check", str(cfg), "--format", "sarif").stdout)
    uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"] \
        ["artifactLocation"]["uri"]
    assert "myconfig.json" in uri


def test_cli_sarif_writes_a_file(tmp_path):
    cfg = tmp_path / "pqc.json"
    cfg.write_text(json.dumps({"largest_object": 12000, "budget": 32768,
                               "concurrency": 3}))
    out = tmp_path / "r.sarif"
    r = run("check", str(cfg), "--format", "sarif", "-o", str(out))
    assert r.returncode == EXIT_FINDING
    assert json.loads(out.read_text())["runs"][0]["results"]
