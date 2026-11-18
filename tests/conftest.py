"""Shared pytest fixtures and helpers.

Puts src on sys.path so `import websift` works without installing
the package, and provides small helpers for writing a snippet of
Python to a temp file and running the scanner over it.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import pytest  # noqa: E402

from websift import rules  # noqa: E402, F401
from websift.registry import restore_rules, run_rules, snapshot_rules  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_rule_registry():
    """Undo any @rule registration a test adds, so a throwaway test
    rule never leaks into another test's findings."""
    snapshot = snapshot_rules()
    yield
    restore_rules(snapshot)


def write_file(tmp_path, name, source):
    """Write source to tmp_path/name, creating parent folders, and
    return its path as a string."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return str(path)


def scan_source(source, path="snippet.py"):
    """Run every registered rule over a snippet of source text.

    Returns (findings, error), matching websift.registry.run_rules.
    """
    return run_rules(path, source)


def findings_for(source, path="snippet.py"):
    """Run the rules over source and return only the findings,
    asserting there was no syntax error."""
    findings, error = scan_source(source, path)
    assert error is None, "unexpected syntax error: " + str(error)
    return findings


