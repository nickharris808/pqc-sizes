"""Adversarial input tests.

Oracle: NO INPUT MAY PRODUCE A CONFIDENT-LOOKING ANSWER THAT IS WRONG.

Two properties matter here and they pull in different directions:

  * a bad *invocation* must be a usage error (exit 2), and
  * a genuine empty window must be a finding (exit 1),

because a CI gate needs to tell "you typed it wrong" apart from "your design is
unsafe". Collapsing them -- which a bare traceback does, and which returning 0 for a
degenerate input would also do -- makes the gate useless.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from pqc_sizes import (
    credential_bytes,
    fragments_for,
    max_concurrent_contexts,
    reassembly_window,
)

EXIT_OK, EXIT_FINDING, EXIT_USAGE = 0, 1, 2


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "pqc_sizes.cli", *args],
                          capture_output=True, text=True, timeout=60)


# ------------------------------------------------------- no tracebacks reach the user

@pytest.mark.parametrize("args", [
    ("window", "--largest-object", "12000", "--budget", "32768", "--concurrency", "0"),
    ("window", "--largest-object", "12000", "--budget", "-5", "--concurrency", "3"),
    ("window", "--largest-object", "0", "--budget", "32768", "--concurrency", "3"),
    ("fragments", "0", "--kem", "ML-KEM-768", "--sig", "ML-DSA-65"),
    ("sweep", "--largest-object", "0", "--budget", "32768", "--max-concurrency", "4"),
])
def test_invalid_input_is_a_clean_usage_error(args):
    r = run(*args)
    assert r.returncode == EXIT_USAGE, f"expected usage error, got {r.returncode}"
    assert "Traceback" not in r.stderr, "a stack trace reached the user"
    assert "Traceback" not in r.stdout


@pytest.mark.parametrize("args", [
    ("window", "--largest-object", "12000", "--budget", "32768", "--concurrency", "0"),
    ("window", "--largest-object", "12000", "--budget", "-5", "--concurrency", "3"),
    ("fragments", "0", "--kem", "ML-KEM-768", "--sig", "ML-DSA-65"),
])
def test_error_names_the_flag_to_change(args):
    """Reporting the problem is not enough; say which flag fixes it."""
    r = run(*args)
    assert "fix:" in r.stderr
    assert "--" in r.stderr.split("fix:")[1]


def test_usage_error_is_distinguishable_from_a_real_finding():
    bad = run("window", "--largest-object", "12000", "--budget", "32768",
              "--concurrency", "0")
    finding = run("window", "--largest-object", "12000", "--budget", "32768",
                  "--concurrency", "3")
    assert bad.returncode == EXIT_USAGE
    assert finding.returncode == EXIT_FINDING
    assert bad.returncode != finding.returncode


# ------------------------------------------------------------------- library-level

@pytest.mark.parametrize("bad", [0, -1, -10**9])
def test_library_rejects_nonpositive_dimensions(bad):
    with pytest.raises(ValueError):
        reassembly_window(bad, 32768, 3)
    with pytest.raises(ValueError):
        reassembly_window(12000, bad, 3)
    with pytest.raises(ValueError):
        reassembly_window(12000, 32768, bad)


def test_unknown_algorithm_names_the_alternatives():
    with pytest.raises(KeyError) as exc:
        credential_bytes("ML-KEM-9999", "ML-DSA-65")
    assert "ML-KEM" in str(exc.value)


# ------------------------------------------------------------- enormous inputs stay exact

def test_enormous_values_stay_exact():
    """Python ints are arbitrary precision; assert we actually rely on that.

    The JS port cannot do this and refuses above 2^53 instead -- see
    pqc-sizes-js/test/precision.test.js. The two must never disagree silently.
    """
    huge = 2 ** 70 + 1
    win = reassembly_window(huge, 2 ** 71, 3)
    assert win.floor == huge
    assert win.ceiling == (2 ** 71) // 3
    assert win.is_empty is True
    assert max_concurrent_contexts(huge, 2 ** 71) == (2 ** 71) // huge


def test_boundary_where_floor_equals_ceiling_is_not_empty():
    """A width-zero window admits exactly one cap; it is not empty."""
    win = reassembly_window(1000, 3000, 3)
    assert win.floor == win.ceiling == 1000
    assert win.is_empty is False
    assert win.admits(1000) is True
    assert win.admits(1001) is False


def test_one_byte_over_the_ceiling_is_empty():
    win = reassembly_window(1001, 3000, 3)
    assert win.ceiling == 1000
    assert win.is_empty is True


def test_max_concurrency_agrees_with_emptiness_everywhere():
    """The derived limit must be the exact tipping point, not an estimate."""
    for obj, budget in [(12000, 32768), (7533, 65536), (1, 10), (999983, 10**9)]:
        limit = max_concurrent_contexts(obj, budget)
        if limit >= 1:
            assert not reassembly_window(obj, budget, limit).is_empty
        assert reassembly_window(obj, budget, limit + 1).is_empty


# -------------------------------------------------------------------- machine output

def test_json_mode_still_signals_through_the_exit_code():
    r = run("--json", "window", "--largest-object", "12000", "--budget", "32768",
            "--concurrency", "3")
    payload = json.loads(r.stdout)
    assert payload["empty"] is True
    assert r.returncode == EXIT_FINDING


def test_fragments_of_a_zero_byte_object_is_zero_not_one():
    assert fragments_for(0, 384) == 0
