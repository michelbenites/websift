import pytest

from websift.model import (
    Finding,
    Severity,
    count_by_severity,
    filter_by_rule,
    group_by_path,
    sort_findings,
    total_count,
)


def make_finding(rule="PY-SQL", cwe=89, severity=Severity.HIGH, path="a.py", line=1, message="msg"):
    return Finding(rule=rule, cwe=cwe, severity=severity, path=path, line=line, message=message)


def test_severity_values():
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"


def test_severity_rank_orders_high_first():
    assert Severity.HIGH.rank < Severity.MEDIUM.rank < Severity.LOW.rank


def test_severity_from_value_valid():
    assert Severity.from_value("high") is Severity.HIGH


def test_severity_from_value_invalid():
    with pytest.raises(ValueError):
        Severity.from_value("critical")


def test_finding_rejects_empty_rule():
    with pytest.raises(ValueError):
        make_finding(rule="")


def test_finding_rejects_non_positive_cwe():
    with pytest.raises(ValueError):
        make_finding(cwe=0)


def test_finding_rejects_bad_severity_type():
    with pytest.raises(ValueError):
        Finding(rule="PY-SQL", cwe=89, severity="high", path="a.py", line=1, message="msg")


def test_finding_rejects_empty_path():
    with pytest.raises(ValueError):
        make_finding(path="")


def test_finding_rejects_line_below_one():
    with pytest.raises(ValueError):
        make_finding(line=0)


def test_finding_rejects_empty_message():
    with pytest.raises(ValueError):
        make_finding(message="")


def test_sort_findings_by_path_then_line():
    f1 = make_finding(path="b.py", line=5)
    f2 = make_finding(path="a.py", line=10)
    f3 = make_finding(path="a.py", line=2)
    ordered = sort_findings([f1, f2, f3])
    assert [f.path + ":" + str(f.line) for f in ordered] == ["a.py:2", "a.py:10", "b.py:5"]


def test_sort_findings_empty():
    assert sort_findings([]) == []


def test_count_by_severity_mixed():
    findings = [
        make_finding(severity=Severity.HIGH),
        make_finding(severity=Severity.HIGH),
        make_finding(severity=Severity.MEDIUM),
        make_finding(severity=Severity.LOW),
    ]
    counts = count_by_severity(findings)
    assert counts == {"high": 2, "medium": 1, "low": 1}


def test_count_by_severity_empty():
    assert count_by_severity([]) == {"high": 0, "medium": 0, "low": 0}


def test_total_count():
    findings = [make_finding(), make_finding()]
    assert total_count(findings) == 2


def test_filter_by_rule():
    findings = [make_finding(rule="PY-SQL"), make_finding(rule="PY-EVAL"), make_finding(rule="PY-SQL")]
    assert len(filter_by_rule(findings, "PY-SQL")) == 2
    assert len(filter_by_rule(findings, "PY-EVAL")) == 1
    assert filter_by_rule(findings, "PY-SHELL") == []


def test_group_by_path():
    findings = [make_finding(path="a.py"), make_finding(path="b.py"), make_finding(path="a.py")]
    grouped = group_by_path(findings)
    assert sorted(grouped.keys()) == ["a.py", "b.py"]
    assert len(grouped["a.py"]) == 2
    assert len(grouped["b.py"]) == 1
