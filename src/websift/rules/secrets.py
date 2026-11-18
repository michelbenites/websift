"""PY-SECRET: a secret-looking name bound directly to a string literal.

Covers four shapes: `NAME = "literal"`, `self.name = "literal"`,
a string key in a dict literal (`{"password": "literal"}`, including
a subscript assignment like `cfg["password"] = "literal"`), and a
keyword argument at a call site (`connect(password="literal")`).
Values coming from a call (os.environ.get, os.getenv, anything else)
are never literals, so they are always fine. Placeholder-looking
literals are not exempted; a literal is a literal.
"""

import ast

from ..config import SECRET_NAME_PATTERNS, rule_info
from ..model import Finding, Severity
from ..pyast import name_matches_patterns, string_literal_value
from ..registry import rule


@rule
def check_secrets(context):
    info = rule_info("PY-SECRET")
    findings = []
    for node in ast.walk(context.tree):
        if isinstance(node, ast.Assign):
            findings.extend(_check_assign_targets(context, node, info))
        elif isinstance(node, ast.AnnAssign):
            findings.extend(_check_ann_assign(context, node, info))
        elif isinstance(node, ast.Dict):
            findings.extend(_check_dict_literal(context, node, info))
        elif isinstance(node, ast.Call):
            findings.extend(_check_keywords(context, node, info))
    return findings


def _check_assign_targets(context, node, info):
    findings = []
    value = string_literal_value(node.value)
    if value is not None and len(value) >= 4:
        for target in node.targets:
            name = _target_name(target)
            if name is not None and name_matches_patterns(name, SECRET_NAME_PATTERNS):
                findings.append(_make_finding(context, node.lineno, info, name))
    findings.extend(_check_tuple_unpack(context, node, info))
    return findings


def _check_tuple_unpack(context, node, info):
    """Handle `user, password = "bob", "changeme123"`: a tuple or list
    assigned to a tuple or list of the same length, matched pairwise."""
    findings = []
    if not isinstance(node.value, (ast.Tuple, ast.List)):
        return findings
    for target in node.targets:
        if not isinstance(target, (ast.Tuple, ast.List)):
            continue
        if len(target.elts) != len(node.value.elts):
            continue
        for name_node, value_node in zip(target.elts, node.value.elts):
            if not isinstance(name_node, ast.Name):
                continue
            literal = string_literal_value(value_node)
            if literal is None or len(literal) < 4:
                continue
            if name_matches_patterns(name_node.id, SECRET_NAME_PATTERNS):
                findings.append(_make_finding(context, node.lineno, info, name_node.id))
    return findings


def _check_ann_assign(context, node, info):
    value = string_literal_value(node.value) if node.value is not None else None
    if value is None or len(value) < 4:
        return []
    name = _target_name(node.target)
    if name is not None and name_matches_patterns(name, SECRET_NAME_PATTERNS):
        return [_make_finding(context, node.lineno, info, name)]
    return []


def _target_name(target):
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        key = _subscript_key(target)
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
    return None


def _subscript_key(node):
    # Python 3.9+ stores the key directly on slice, no ast.Index wrapper.
    return node.slice


def _check_dict_literal(context, node, info):
    findings = []
    for key, value in zip(node.keys, node.values):
        if key is None:
            continue
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            continue
        literal = string_literal_value(value)
        if literal is None or len(literal) < 4:
            continue
        if name_matches_patterns(key.value, SECRET_NAME_PATTERNS):
            findings.append(_make_finding(context, key.lineno, info, key.value))
    return findings


def _check_keywords(context, node, info):
    findings = []
    for kw in node.keywords:
        if kw.arg is None:
            continue
        literal = string_literal_value(kw.value)
        if literal is None or len(literal) < 4:
            continue
        if name_matches_patterns(kw.arg, SECRET_NAME_PATTERNS):
            findings.append(_make_finding(context, node.lineno, info, kw.arg))
    return findings


def _make_finding(context, line, info, name):
    return Finding(
        rule=info.rule,
        cwe=info.cwe,
        severity=Severity(info.severity),
        path=context.path,
        line=line,
        message="possible hardcoded secret in " + name,
    )
