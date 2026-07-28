"""SARIF output, so an empty reassembly window lands in GitHub code scanning.

An empty window is a design defect that is invisible in code review and cheap to
detect. Putting it in the Security tab, anchored to the config file that causes
it, is the difference between a tool someone runs once and a tool that keeps
watching.

Deliberately not emitted as a "note". An empty window means no capacity cap is
both feasible and safe; there is no advisory reading of that.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .core import Window

SARIF_VERSION = "2.1.0"
#: The OASIS canonical URL. The commonly-pasted raw.githubusercontent.com
#: /oasis-tcs/sarif-spec/master/Schemata/... address is a 404.
SARIF_SCHEMA = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
                "schemas/sarif-schema-2.1.0.json")

_RULES = [
    {
        "id": "pqc-sizes/empty-window",
        "name": "EmptyReassemblyWindow",
        "shortDescription": {"text": "No safe reassembly capacity cap exists"},
        "fullDescription": {"text": (
            "The largest legitimate object exceeds the memory budget divided by "
            "worst-case concurrency, so no cap is both feasible (large enough to "
            "accept honest peers) and safe (small enough that concurrent contexts "
            "cannot exhaust the budget). This is a design answer, not a warning: "
            "raise the budget, reduce concurrency, or choose a smaller credential.")},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://github.com/nickharris808/pqc-sizes#why-this-exists",
    },
]


def sarif_report(window: Window, max_safe_concurrency: int,
                 config_path: str = "pqc.json") -> dict:
    """A SARIF 2.1.0 log for one window verdict."""
    results = []
    if window.is_empty:
        results.append({
            "ruleId": "pqc-sizes/empty-window",
            "level": "error",
            "message": {"text": window.explain()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": config_path},
                "region": {"startLine": 1},
            }}],
            "properties": {
                "floor": window.floor,
                "ceiling": window.ceiling,
                "budget": window.budget,
                "concurrency": window.concurrency,
                "max_safe_concurrency": max_safe_concurrency,
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "pqc-sizes",
                "informationUri": "https://github.com/nickharris808/pqc-sizes",
                "rules": _RULES,
            }},
            "results": results,
        }],
    }


def write_sarif(window: Window, max_safe_concurrency: int,
                config_path: str = "pqc.json", output: str | None = None) -> str:
    text = json.dumps(sarif_report(window, max_safe_concurrency, config_path), indent=2)
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return text
