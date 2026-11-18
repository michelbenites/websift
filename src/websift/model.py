"""Finding data model and helpers for sorting and counting.

A Finding is immutable and validates its own fields on creation, so a
rule that builds a bad Finding fails loudly instead of producing a
broken report later.
"""

from dataclasses import dataclass
from enum import Enum

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


class Severity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self):
        return _SEVERITY_RANK[self.value]

    @classmethod
    def from_value(cls, value):
        """Build a Severity from its plain string, with a clear error
        message when the value is not one of high, medium or low."""
        try:
            return cls(value)
        except ValueError:
            raise ValueError("unknown severity: " + str(value))


@dataclass(frozen=True)
class Finding:
    rule: str
    cwe: int
    severity: Severity
    path: str
    line: int
    message: str

    def __post_init__(self):
        if not self.rule:
            raise ValueError("rule must not be empty")
        if not isinstance(self.cwe, int) or self.cwe <= 0:
            raise ValueError("cwe must be a positive integer")
        if not isinstance(self.severity, Severity):
            raise ValueError("severity must be a Severity value")
        if not self.path:
            raise ValueError("path must not be empty")
        if not isinstance(self.line, int) or self.line < 1:
            raise ValueError("line must be 1 or greater")
        if not self.message:
            raise ValueError("message must not be empty")

    def sort_key(self):
        return (self.path, self.line)


def sort_findings(findings):
    """Sort findings by file path, then by line number.

    Findings on the same file and line keep their original relative
    order, since Python's sort is stable and this only needs a total
    order across files and lines.
    """
    return sorted(findings, key=lambda finding: finding.sort_key())


def count_by_severity(findings):
    """Return a dict with counts for high, medium and low severities."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def total_count(findings):
    return len(findings)


def filter_by_rule(findings, rule_name):
    """Return only the findings for one rule. Mostly useful for tests
    that want to check one rule's output among many findings."""
    return [finding for finding in findings if finding.rule == rule_name]


def group_by_path(findings):
    """Group findings into a dict keyed by file path, preserving the
    relative order findings were given in within each group."""
    grouped = {}
    for finding in findings:
        grouped.setdefault(finding.path, []).append(finding)
    return grouped
