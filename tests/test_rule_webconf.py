import pytest

from conftest import findings_for


def debug_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-DEBUG"]


def cors_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-CORS"]


def cookie_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-COOKIE"]


@pytest.mark.parametrize(
    "source",
    [
        "app.run(debug=True)\n",
        "app.run(host='0.0.0.0', debug=True)\n",
        "app.debug = True\n",
        'app.config["DEBUG"] = True\n',
        'app.config["debug"] = True\n',
        "app.config.update(DEBUG=True)\n",
    ],
)
def test_debug_enabled_flagged(source):
    findings = debug_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 489
    assert findings[0].severity.value == "medium"


@pytest.mark.parametrize(
    "source",
    [
        "app.run(debug=False)\n",
        "app.run()\n",
        "app.debug = False\n",
        'app.config["DEBUG"] = False\n',
        'app.config["OTHER"] = True\n',
        "app.config.update(DEBUG=False)\n",
    ],
)
def test_debug_disabled_not_flagged(source):
    assert debug_findings(source) == []


@pytest.mark.parametrize(
    "source",
    [
        'CORS(app, origins="*")\n',
        'CORS(app, origins=["*"])\n',
        'CORS(app, origins=["https://a.test", "*"])\n',
        'from flask_cors import CORS\nCORS(app, origins="*")\n',
    ],
)
def test_cors_wildcard_origin_flagged(source):
    findings = cors_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 942
    assert findings[0].severity.value == "medium"


@pytest.mark.parametrize(
    "source",
    [
        'CORS(app, origins=["https://a.test"])\n',
        "CORS(app)\n",
        'CORS(app, origins="https://a.test")\n',
    ],
)
def test_cors_specific_origin_not_flagged(source):
    assert cors_findings(source) == []


def test_cors_header_dict_wildcard_flagged():
    source = 'headers = {"Access-Control-Allow-Origin": "*"}\n'
    findings = cors_findings(source)
    assert len(findings) == 1


def test_cors_header_dict_specific_not_flagged():
    source = 'headers = {"Access-Control-Allow-Origin": "https://a.test"}\n'
    assert cors_findings(source) == []


@pytest.mark.parametrize(
    "source",
    [
        'resp.set_cookie("id", value)\n',
        'resp.set_cookie("id", value, secure=True)\n',
        'resp.set_cookie("id", value, httponly=True)\n',
        'resp.set_cookie("id", value, secure=False, httponly=True)\n',
        'resp.set_cookie("id", value, secure=True, httponly=False)\n',
    ],
)
def test_cookie_missing_flags_flagged(source):
    findings = cookie_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 614
    assert findings[0].severity.value == "low"


def test_cookie_message_names_missing_flags():
    source = 'resp.set_cookie("id", value)\n'
    message = cookie_findings(source)[0].message
    assert "secure=True" in message
    assert "httponly=True" in message


def test_cookie_message_names_only_missing_secure():
    source = 'resp.set_cookie("id", value, httponly=True)\n'
    message = cookie_findings(source)[0].message
    assert "secure=True" in message
    assert "httponly=True" not in message


def test_cookie_with_both_flags_not_flagged():
    source = 'resp.set_cookie("id", value, secure=True, httponly=True)\n'
    assert cookie_findings(source) == []


def test_cookie_with_extra_flags_still_safe():
    source = 'resp.set_cookie("id", value, secure=True, httponly=True, samesite="Lax")\n'
    assert cookie_findings(source) == []


def test_unrelated_call_named_similarly_not_flagged():
    source = "set_cookie_jar(path)\n"
    assert cookie_findings(source) == []
