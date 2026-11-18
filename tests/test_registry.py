import pytest

from websift.model import Finding, Severity
from websift.registry import Context, parse_source, registered_rule_count, registered_rules, rule, run_rules


def test_rule_decorator_registers_function():
    before = registered_rule_count()

    @rule
    def my_test_rule(context):
        return []

    after = registered_rule_count()
    assert after == before + 1
    assert my_test_rule in registered_rules()


def test_parse_source_success():
    tree, error = parse_source("a.py", "x = 1\n")
    assert error is None and tree is not None


def test_parse_source_syntax_error():
    tree, error = parse_source("a.py", "def f(:\n")
    assert tree is None
    assert error is not None


def test_context_builds_parent_and_import_maps():
    tree, _ = parse_source("a.py", "import pickle as pk\npk.loads(x)\n")
    context = Context("a.py", tree)
    assert context.path == "a.py"
    assert context.import_map == {"pk": "pickle"} and len(context.parent_map) > 0


def test_run_rules_runs_registered_rules_and_collects_findings():
    @rule
    def always_one_finding(context):
        return [
            Finding(
                rule="PY-TEST",
                cwe=1,
                severity=Severity.LOW,
                path=context.path,
                line=1,
                message="test finding",
            )
        ]

    findings, error = run_rules("a.py", "x = 1\n")
    assert error is None
    assert any(f.rule == "PY-TEST" for f in findings)


def test_run_rules_returns_error_on_syntax_error():
    findings, error = run_rules("a.py", "def broken(:\n")
    assert findings == []
    assert error is not None


def test_run_rules_rejects_rule_returning_non_finding():
    @rule
    def broken_rule(context):
        return ["not a finding"]

    with pytest.raises(TypeError):
        run_rules("a.py", "x = 1\n")
