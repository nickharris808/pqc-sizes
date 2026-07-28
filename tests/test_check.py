"""Tests for `pqc-sizes check` — gating on a committed config file.

Every error path here is asserted to name the *fix*, not just the problem. A CI
tool that says "invalid config" and stops has moved the debugging onto whoever
is least equipped to do it: the person who just wanted a green build.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

EXIT_OK, EXIT_FINDING, EXIT_USAGE = 0, 1, 2


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "pqc_sizes.cli", *args],
                          capture_output=True, text=True, timeout=60)


def write(tmp_path, obj, name="pqc.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(obj) if isinstance(obj, dict) else obj)
    return str(p)


# ------------------------------------------------------------------- happy paths

def test_safe_config_exits_zero(tmp_path):
    cfg = write(tmp_path, {"kem": "ML-KEM-768", "sig": "ML-DSA-65",
                           "budget": 65536, "concurrency": 4})
    r = run("check", cfg)
    assert r.returncode == EXIT_OK
    assert "7,533 B object" in r.stdout


def test_unsafe_config_exits_one(tmp_path):
    """A hash-based signature blows the window; the gate must fail the build."""
    cfg = write(tmp_path, {"kem": "ML-KEM-768", "sig": "SLH-DSA-SHA2-128f",
                           "budget": 65536, "concurrency": 4})
    r = run("check", cfg)
    assert r.returncode == EXIT_FINDING
    assert "EMPTY WINDOW" in r.stdout


def test_explicit_largest_object_needs_no_suite(tmp_path):
    cfg = write(tmp_path, {"largest_object": 12000, "budget": 32768, "concurrency": 3})
    assert run("check", cfg).returncode == EXIT_FINDING


def test_json_output_and_exit_code_agree(tmp_path):
    cfg = write(tmp_path, {"largest_object": 12000, "budget": 32768, "concurrency": 3})
    r = run("--json", "check", cfg)
    assert json.loads(r.stdout)["empty"] is True
    assert r.returncode == EXIT_FINDING


# ------------------------------------------------ every error names its remedy

@pytest.mark.parametrize("cfg,needle", [
    ({"kem": "ML-KEM-768", "sig": "ML-DSA-65", "budgett": 1, "concurrency": 4},
     "valid keys are"),
    ({"kem": "ML-KEM-768", "sig": "ML-DSA-65", "concurrency": 4},
     "budget is total reassembly bytes"),
    ({"kem": "NOPE", "sig": "ML-DSA-65", "budget": 1, "concurrency": 4},
     "pqc-sizes sizes"),
    ({"budget": 65536, "concurrency": 4},
     "add \"kem\" and \"sig\""),
])
def test_bad_config_explains_the_fix(tmp_path, cfg, needle):
    r = run("check", write(tmp_path, cfg))
    assert r.returncode == EXIT_USAGE
    assert "fix:" in r.stderr
    assert needle in r.stderr
    assert "Traceback" not in r.stderr


def test_missing_file_shows_a_starter_config():
    r = run("check", "/nonexistent/pqc.json")
    assert r.returncode == EXIT_USAGE
    assert "ML-KEM-768" in r.stderr      # a config you can paste


def test_a_non_mapping_config_is_rejected(tmp_path):
    r = run("check", write(tmp_path, "[1, 2, 3]"))
    assert r.returncode == EXIT_USAGE


def test_usage_error_is_distinct_from_a_finding(tmp_path):
    """A broken config must not look like an unsafe design, or vice versa."""
    broken = run("check", write(tmp_path, {"nonsense": 1}, "a.json"))
    finding = run("check", write(tmp_path, {"largest_object": 12000, "budget": 32768,
                                            "concurrency": 3}, "b.json"))
    assert broken.returncode == EXIT_USAGE
    assert finding.returncode == EXIT_FINDING
    assert broken.returncode != finding.returncode
