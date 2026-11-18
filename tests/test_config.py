import pytest

from websift.config import RuleInfo, rule_info, rule_names


def test_rule_info_known_rule():
    info = rule_info("PY-SQL")
    assert info.rule == "PY-SQL"
    assert info.cwe == 89
    assert info.severity == "high"


def test_rule_info_unknown_rule_raises():
    with pytest.raises(KeyError):
        rule_info("PY-NOT-A-RULE")


def test_rule_names_sorted_and_complete():
    names = rule_names()
    assert names == sorted(names)
    expected = {
        "PY-SQL",
        "PY-SECRET",
        "PY-HASH",
        "PY-RANDOM",
        "PY-EVAL",
        "PY-SHELL",
        "PY-PICKLE",
        "PY-DEBUG",
        "PY-CORS",
        "PY-COOKIE",
    }
    assert set(names) == expected


def test_rule_info_severity_for_every_rule():
    for name in rule_names():
        info = rule_info(name)
        assert info.severity in ("high", "medium", "low")


def test_rule_info_rejects_bad_severity():
    with pytest.raises(ValueError):
        RuleInfo("PY-FAKE", 1, "critical")


def test_rule_info_rejects_bad_cwe():
    with pytest.raises(ValueError):
        RuleInfo("PY-FAKE", 0, "high")

    with pytest.raises(ValueError):
        RuleInfo("PY-FAKE", -5, "high")
