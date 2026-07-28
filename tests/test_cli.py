"""Tests for the command line interface.

The CLI is the first thing a new user runs -- it is the README quickstart --
so its exit codes and its output shape are part of the public contract, not
incidental formatting. These tests drive the real entry point in a subprocess
rather than calling ``main()``, because the exit code and the stdout/stderr
split are exactly what a CI pipeline consumes.
"""

from __future__ import annotations

import subprocess
import sys

import pytest


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pqc_sizes.cli", *args],
        capture_output=True, text=True, timeout=60,
    )


def test_empty_window_exits_nonzero():
    """The empty-window verdict must be actionable from a shell.

    pqc-guard-action and any plain `&&` chain rely on this; if it ever
    returned 0 the whole CI story would silently pass broken configs.
    """
    r = run("window", "--largest-object", "12000",
            "--budget", "32768", "--concurrency", "3")
    assert r.returncode == 1
    assert "EMPTY WINDOW" in r.stdout


def test_satisfiable_window_exits_zero():
    r = run("window", "--largest-object", "7533",
            "--budget", "65536", "--concurrency", "4")
    assert r.returncode == 0
    assert "EMPTY" not in r.stdout


@pytest.mark.parametrize("args", [
    ("window", "--largest-object", "12000", "--budget", "32768",
     "--concurrency", "3"),
    ("fragments", "wifi-mgmt-frag", "--kem", "ML-KEM-768", "--sig", "ML-DSA-65"),
    ("sweep", "--largest-object", "12000", "--budget", "32768",
     "--max-concurrency", "4"),
])
def test_prose_is_wrapped_for_a_terminal(args):
    """No output line may overflow a classic 80-column terminal.

    Prose is wrapped at 78 to leave margin; the bound asserted here is 80,
    the terminal width itself, so a one-off label line sitting at 79 is not
    forced into an ugly two-line break. ``Window.explain()`` deliberately
    returns one unbroken string -- the MCP server embeds it in JSON and the
    Action in an annotation -- so wrapping is the CLI's job alone, and
    nothing asserted it until now.
    """
    r = run(*args)
    over = [ln for ln in r.stdout.splitlines() if len(ln) > 80]
    assert not over, f"lines exceeding 80 cols: {over}"


def test_window_json_is_machine_readable():
    """--json is a *global* flag: it precedes the subcommand."""
    import json
    r = run("--json", "window", "--largest-object", "12000",
            "--budget", "32768", "--concurrency", "3")
    payload = json.loads(r.stdout)
    assert payload["empty"] is True
    assert payload["ceiling"] == 10922
    assert payload["max_safe_concurrency"] == 2
    # --json must still signal through the exit code, not only the body.
    assert r.returncode == 1


def test_credential_totals_match_the_documented_value():
    r = run("credential", "--kem", "ML-KEM-768", "--sig", "ML-DSA-65")
    assert r.returncode == 0
    assert "7,533 B" in r.stdout


def test_unknown_algorithm_fails_with_a_useful_message():
    r = run("credential", "--kem", "ML-KEM-9999", "--sig", "ML-DSA-65")
    assert r.returncode != 0
    assert "unknown algorithm" in r.stderr.lower()
