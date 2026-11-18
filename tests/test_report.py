import io

from websift.model import Finding, Severity
from websift.report import (
    format_finding,
    format_severity_counts,
    format_summary,
    format_syntax_warning,
    format_usage_error,
    has_high_severity,
    render,
    render_lines,
    write_report,
    write_warnings,
)


def make_finding(rule="PY-SQL", cwe=89, severity=Severity.HIGH, path="a.py", line=3, message="bad query"):
    return Finding(rule=rule, cwe=cwe, severity=severity, path=path, line=line, message=message)


def test_format_finding_matches_expected_shape():
    finding = make_finding(path="app/views.py", line=42)
    line = format_finding(finding)
    assert line == "app/views.py:42: [high] PY-SQL (CWE-89) bad query"


def test_format_summary_zero_findings():
    assert format_summary([]) == "Summary: 0 findings (0 high, 0 medium, 0 low)"


def test_format_summary_with_counts():
    findings = [
        make_finding(severity=Severity.HIGH),
        make_finding(severity=Severity.MEDIUM),
        make_finding(severity=Severity.MEDIUM),
        make_finding(severity=Severity.LOW),
    ]
    assert format_summary(findings) == "Summary: 4 findings (1 high, 2 medium, 1 low)"


def test_format_severity_counts_order():
    counts = {"high": 3, "medium": 1, "low": 0}
    assert format_severity_counts(counts) == "3 high, 1 medium, 0 low"


def test_render_lines_sorted_with_summary_last():
    f1 = make_finding(path="b.py", line=1)
    f2 = make_finding(path="a.py", line=5)
    lines = render_lines([f1, f2])
    assert lines[0].startswith("a.py:5:")
    assert lines[1].startswith("b.py:1:")
    assert lines[-1].startswith("Summary:")


def test_render_lines_no_findings_still_has_summary():
    lines = render_lines([])
    assert lines == ["Summary: 0 findings (0 high, 0 medium, 0 low)"]


def test_render_joins_with_newlines():
    f1 = make_finding(path="a.py", line=1)
    text = render([f1])
    assert text.count("\n") == 1
    assert text.endswith("Summary: 1 findings (1 high, 0 medium, 0 low)")


def test_format_syntax_warning():
    message = format_syntax_warning("broken.py", "invalid syntax (broken.py, line 3)")
    assert message == "warning: skipping broken.py, syntax error: invalid syntax (broken.py, line 3)"


def test_format_syntax_warning_uses_first_line_only():
    message = format_syntax_warning("broken.py", "line one\nline two")
    assert "line two" not in message
    assert "line one" in message


def test_format_usage_error():
    assert format_usage_error("PATH is not a folder") == "error: PATH is not a folder"


def test_write_report_prints_every_line(capsys):
    f1 = make_finding(path="a.py", line=1)
    out = io.StringIO()
    write_report([f1], out)
    text = out.getvalue()
    assert "a.py:1:" in text
    assert text.strip().endswith("Summary: 1 findings (1 high, 0 medium, 0 low)")


def test_write_report_empty_still_prints_summary():
    out = io.StringIO()
    write_report([], out)
    assert out.getvalue().strip() == "Summary: 0 findings (0 high, 0 medium, 0 low)"


def test_write_warnings_prints_each_one():
    out = io.StringIO()
    write_warnings(["warning: one", "warning: two"], out)
    lines = out.getvalue().splitlines()
    assert lines == ["warning: one", "warning: two"]


def test_write_warnings_empty_prints_nothing():
    out = io.StringIO()
    write_warnings([], out)
    assert out.getvalue() == ""


def test_has_high_severity_true():
    assert has_high_severity([make_finding(severity=Severity.HIGH)]) is True


def test_has_high_severity_false_without_high():
    findings = [make_finding(severity=Severity.MEDIUM), make_finding(severity=Severity.LOW)]
    assert has_high_severity(findings) is False


def test_has_high_severity_false_when_empty():
    assert has_high_severity([]) is False
