"""PY-DEBUG, PY-CORS and PY-COOKIE: web framework misconfiguration.

PY-DEBUG fires for debug=True on any call, app.debug = True, or
app.config["DEBUG"] = True. PY-CORS fires for CORS(...) configured
with a wildcard origin, or a response header setting
Access-Control-Allow-Origin to "*". PY-COOKIE fires for a set_cookie
call missing secure=True or httponly=True.
"""

import ast

from ..config import rule_info
from ..model import Finding, Severity
from ..pyast import dotted_name, get_keyword, is_constant_string, is_true_constant
from ..registry import rule

_CORS_HEADER = "Access-Control-Allow-Origin"


@rule
def check_debug(context):
    info = rule_info("PY-DEBUG")
    findings = []
    for node in ast.walk(context.tree):
        if isinstance(node, ast.Call):
            debug_kw = get_keyword(node, "debug")
            if debug_kw is not None and is_true_constant(debug_kw):
                findings.append(_make_finding(context, node.lineno, info, "debug mode enabled"))
            elif _is_config_update(node):
                update_debug = get_keyword(node, "DEBUG")
                if update_debug is not None and is_true_constant(update_debug):
                    findings.append(_make_finding(context, node.lineno, info, "debug mode enabled"))
        elif isinstance(node, ast.Assign) and is_true_constant(node.value):
            for target in node.targets:
                if _is_debug_attribute(target) or _is_debug_config_key(target):
                    findings.append(_make_finding(context, node.lineno, info, "debug mode enabled"))
    return findings


def _is_config_update(node):
    name = dotted_name(node.func)
    if name is None:
        return False
    parts = name.split(".")
    return len(parts) >= 2 and parts[-1] == "update" and parts[-2] == "config"


def _is_debug_attribute(target):
    return isinstance(target, ast.Attribute) and target.attr == "debug"


def _is_debug_config_key(target):
    if not isinstance(target, ast.Subscript):
        return False
    key = target.slice
    if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
        return False
    if key.value.upper() != "DEBUG":
        return False
    base = target.value
    if isinstance(base, ast.Attribute):
        return base.attr == "config"
    if isinstance(base, ast.Name):
        return base.id == "config"
    return False


@rule
def check_cors(context):
    info = rule_info("PY-CORS")
    findings = []
    for node in ast.walk(context.tree):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name is not None and name.split(".")[-1] == "CORS":
                origins = get_keyword(node, "origins")
                if origins is not None and _is_wildcard(origins):
                    findings.append(_make_finding(context, node.lineno, info, 'CORS configured with origins="*"'))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == _CORS_HEADER and _is_wildcard_string(value):
                    findings.append(_make_finding(context, key.lineno, info, "Access-Control-Allow-Origin set to *"))
    return findings


def _is_wildcard(node):
    if _is_wildcard_string(node):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_is_wildcard_string(elt) for elt in node.elts)
    return False


def _is_wildcard_string(node):
    return is_constant_string(node) and node.value == "*"


@rule
def check_cookie(context):
    info = rule_info("PY-COOKIE")
    findings = []
    for node in ast.walk(context.tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        if name is None or name.split(".")[-1] != "set_cookie":
            continue

        secure_ok = is_true_constant(get_keyword(node, "secure") or ast.Constant(value=False))
        httponly_ok = is_true_constant(get_keyword(node, "httponly") or ast.Constant(value=False))
        if secure_ok and httponly_ok:
            continue

        missing = []
        if not secure_ok:
            missing.append("secure=True")
        if not httponly_ok:
            missing.append("httponly=True")
        message = "set_cookie missing " + " and ".join(missing)
        findings.append(_make_finding(context, node.lineno, info, message))
    return findings


def _make_finding(context, line, info, message):
    return Finding(
        rule=info.rule,
        cwe=info.cwe,
        severity=Severity(info.severity),
        path=context.path,
        line=line,
        message=message,
    )
