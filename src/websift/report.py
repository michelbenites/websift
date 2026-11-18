"""Renders findings and the final summary as plain text.

Each finding prints as one line:
    PATH:LINE: [severity] RULE (CWE-n) message
Findings are sorted by file, then by line. The report always ends
with one summary line, even when there are no findings at all.
"""

from .model import count_by_severity, sort_findings

_SEVERITY_ORDER = ("high", "medium", "low")


def format_finding(finding):
    return "{path}:{line}: [{severity}] {rule} (CWE-{cwe}) {message}".format(
        path=finding.path,
        line=finding.line,
        severity=finding.severity.value,
        rule=finding.rule,
        cwe=finding.cwe,
        message=finding.message,
    )


def format_severity_counts(counts):
    """Format the (high, medium, low) part of the summary line."""
    parts = ["{count} {label}".format(count=counts[label], label=label) for label in _SEVERITY_ORDER]
    return ", ".join(parts)


def format_summary(findings):
    counts = count_by_severity(findings)
    return "Summary: {total} findings ({breakdown})".format(
        total=len(findings),
        breakdown=format_severity_counts(counts),
    )


def render_lines(findings):
    """Return the report as a list of lines: one per finding, in
    sorted order, with the summary line last."""
    ordered = sort_findings(findings)
    lines = [format_finding(finding) for finding in ordered]
    lines.append(format_summary(findings))
    return lines


def render(findings):
    """Return the full text report as a single string."""
    return "\n".join(render_lines(findings))


def format_syntax_warning(path, message):
    first_line = message.splitlines()[0] if message else "invalid syntax"
    return "warning: skipping {path}, syntax error: {message}".format(path=path, message=first_line)


def format_usage_error(message):
    return "error: " + message


def write_report(findings, out):
    """Print the findings and summary to the given stream."""
    for line in render_lines(findings):
        print(line, file=out)


def write_warnings(warnings, err):
    """Print one syntax-error warning per skipped file to the given
    stream, in the order the files were scanned."""
    for warning in warnings:
        print(warning, file=err)


def has_high_severity(findings):
    """True if at least one finding is high severity.

    Not used for the exit code (any finding at all means exit 1), but
    useful for anything that wants to react only to the worst cases.
    """
    counts = count_by_severity(findings)
    return counts["high"] > 0
