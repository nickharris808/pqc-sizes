"""`pqc-sizes budget` — the inverse solver.

`window` answers "is my budget enough?". Users start one step earlier: they have
a credential and a concurrency target and need the budget. The property under
test is that the two commands agree exactly at the boundary — a budget this
command calls sufficient must not produce an empty window, and one byte less must.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from pqc_sizes import credential_bytes, reassembly_window

EXIT_OK, EXIT_USAGE = 0, 2


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "pqc_sizes.cli", *args],
                          capture_output=True, text=True, timeout=60)


def required_for(obj: int, conc: int) -> int:
    payload = json.loads(
        run("--json", "budget", "--largest-object", str(obj),
            "--concurrency", str(conc)).stdout)
    return payload["required_budget"]


# ------------------------------------------------------- agreement with `window`

@pytest.mark.parametrize("obj,conc", [
    (7533, 4), (12000, 3), (19392, 8), (1, 1), (65535, 16),
])
def test_the_required_budget_is_exactly_sufficient(obj, conc):
    """The boundary must be tight in both directions, or the number is a guess."""
    required = required_for(obj, conc)
    assert not reassembly_window(obj, required, conc).is_empty, "not sufficient"
    if required - 1 >= 1:
        # A budget of 0 is not "an empty window", it is invalid input, so the
        # minimality check only applies where one-byte-less is still a legal budget.
        assert reassembly_window(obj, required - 1, conc).is_empty, "not minimal"


def test_credential_path_agrees_with_the_explicit_path():
    payload = json.loads(
        run("--json", "budget", "--kem", "ML-KEM-768", "--sig", "ML-DSA-65",
            "--concurrency", "4").stdout)
    assert payload["largest_object"] == credential_bytes("ML-KEM-768", "ML-DSA-65")
    assert payload["required_budget"] == required_for(payload["largest_object"], 4)


def test_headroom_multiples_are_what_they_say():
    payload = json.loads(
        run("--json", "budget", "--largest-object", "7533", "--concurrency", "4").stdout)
    base = payload["required_budget"]
    assert payload["headroom_at"]["2"] == base * 2
    assert payload["headroom_at"]["4"] == base * 4


def test_output_warns_that_the_minimum_leaves_no_headroom():
    """A budget that admits exactly one cap value is a fragile answer, and the
    command says so rather than presenting it as comfortable."""
    r = run("budget", "--kem", "ML-KEM-768", "--sig", "ML-DSA-65", "--concurrency", "4")
    assert "single point" in r.stdout
    assert "no headroom" in r.stdout


# --------------------------------------------------------------------- bad input

def test_missing_object_and_suite_is_a_usage_error():
    r = run("budget", "--concurrency", "4")
    assert r.returncode == EXIT_USAGE
    assert "--largest-object" in r.stderr


def test_unknown_algorithm_is_a_usage_error():
    r = run("budget", "--kem", "NOPE", "--sig", "ML-DSA-65", "--concurrency", "4")
    assert r.returncode == EXIT_USAGE
    assert "pqc-sizes sizes" in r.stderr


@pytest.mark.parametrize("conc", ["0", "-1"])
def test_nonpositive_concurrency_is_refused(conc):
    """Zero contexts is not a deployment; it is a typo."""
    r = run("budget", "--largest-object", "7533", "--concurrency", conc)
    assert r.returncode != EXIT_OK
    assert "Traceback" not in r.stderr


def test_enormous_values_stay_exact():
    obj = 2 ** 40 + 1
    payload = json.loads(
        run("--json", "budget", "--largest-object", str(obj),
            "--concurrency", "1000").stdout)
    assert payload["required_budget"] == obj * 1000
