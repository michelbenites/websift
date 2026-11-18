import pytest

from conftest import findings_for


def secret_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-SECRET"]


@pytest.mark.parametrize(
    "source",
    [
        'PASSWORD = "changeme123"\n',
        'passwd = "changeme123"\n',
        'SECRET = "changeme123"\n',
        'API_KEY = "changeme123"\n',
        'apikey = "changeme123"\n',
        'TOKEN = "changeme123"\n',
        'DB_PASSWORD = "changeme123"\n',
        'self.password = "changeme123"\n',
        'config["password"] = "changeme123"\n',
        'f(password="changeme123")\n',
    ],
)
def test_name_patterns_flagged(source):
    findings = secret_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 798
    assert findings[0].severity.value == "high"


def test_dict_literal_key_flagged():
    source = 'cfg = {"password": "changeme123"}\n'
    findings = secret_findings(source)
    assert len(findings) == 1


def test_ann_assign_flagged():
    source = 'SECRET_KEY: str = "changeme123"\n'
    findings = secret_findings(source)
    assert len(findings) == 1


def test_tuple_unpack_flagged():
    source = 'user, password = "bob", "changeme123"\n'
    findings = secret_findings(source)
    assert len(findings) == 1


def test_tuple_unpack_mismatched_length_not_flagged():
    source = 'user, password, extra = "bob", "changeme123"\n'
    assert secret_findings(source) == []


def test_chained_assignment_both_targets_flagged():
    source = 'a_token = b_token = "changeme123"\n'
    findings = secret_findings(source)
    assert len(findings) == 2


@pytest.mark.parametrize(
    "source",
    [
        'PASSWORD = os.environ["PASSWORD"]\n',
        'PASSWORD = os.environ.get("PASSWORD")\n',
        'PASSWORD = os.getenv("PASSWORD")\n',
        "PASSWORD = fetch_password()\n",
        'PASSWORD = "abc"\n',
        'NAME = "changeme123"\n',
        'f(password=get_password())\n',
        'cfg = {"password": fetch()}\n',
    ],
)
def test_safe_variants_not_flagged(source):
    assert secret_findings(source) == []


def test_placeholder_looking_value_still_flagged():
    source = 'API_TOKEN = "changeme-fake-api-token"\n'
    findings = secret_findings(source)
    assert len(findings) == 1


def test_short_literal_not_flagged():
    source = 'PASSWORD = "abc"\n'
    assert secret_findings(source) == []


def test_minimum_length_literal_flagged():
    source = 'PASSWORD = "abcd"\n'
    findings = secret_findings(source)
    assert len(findings) == 1


def test_case_insensitive_pattern_match():
    source = 'MyPassWord = "changeme123"\n'
    findings = secret_findings(source)
    assert len(findings) == 1


def test_non_matching_dict_key_not_flagged():
    source = 'cfg = {"username": "changeme123"}\n'
    assert secret_findings(source) == []


def test_subscript_with_dynamic_key_not_flagged():
    source = 'cfg[key_name] = "changeme123"\n'
    assert secret_findings(source) == []


def test_multiple_findings_counted_separately():
    source = 'SECRET_KEY = "changeme123"\nAPI_TOKEN = "changeme456"\n'
    findings = secret_findings(source)
    assert len(findings) == 2
