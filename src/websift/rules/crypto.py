"""PY-HASH and PY-RANDOM: weak hashing and weak randomness for
security-sensitive values.

PY-HASH fires for hashlib.md5/sha1, or hashlib.new("md5"/"sha1"),
when the data being hashed mentions a password-like name. sha256 and
other algorithms are never reported.

PY-RANDOM fires for a call into the random module when it is assigned
to, or sits inside a function named after, something that looks like
a security token. The secrets module is never reported.
"""

import ast

from ..config import (
    PASSWORD_LIKE_PATTERNS,
    RANDOM_FUNCTION_NAMES,
    TOKEN_LIKE_PATTERNS,
    WEAK_HASH_NAMES,
    rule_info,
)
from ..model import Finding, Severity
from ..pyast import enclosing_function, name_matches_patterns, resolve_call_name, string_literal_value
from ..registry import rule


@rule
def check_weak_hash(context):
    info = rule_info("PY-HASH")
    findings = []
    for node in ast.walk(context.tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = resolve_call_name(node, context.import_map)
        if resolved is None:
            continue

        data_args = _weak_hash_data_args(resolved, node)
        if data_args is None:
            continue
        if any(_mentions_pattern(arg, PASSWORD_LIKE_PATTERNS) for arg in data_args):
            findings.append(_make_finding(context, node.lineno, info, "weak hash used on a password-like value"))
    return findings


def _weak_hash_data_args(resolved, node):
    keyword_values = [kw.value for kw in node.keywords if kw.arg is not None]
    if resolved in ("hashlib.md5", "hashlib.sha1"):
        return list(node.args) + keyword_values
    if resolved == "hashlib.new" and node.args:
        algo = string_literal_value(node.args[0])
        if algo is not None and algo.lower() in WEAK_HASH_NAMES:
            return list(node.args[1:]) + keyword_values
    return None


@rule
def check_weak_random(context):
    info = rule_info("PY-RANDOM")
    findings = []
    for node in ast.walk(context.tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = resolve_call_name(node, context.import_map)
        if resolved is None:
            continue
        parts = resolved.split(".")
        if parts[0] != "random" or parts[-1] not in RANDOM_FUNCTION_NAMES:
            continue

        assign_name = _enclosing_assign_name(node, context.parent_map)
        func = enclosing_function(node, context.parent_map)
        matched = (assign_name is not None and name_matches_patterns(assign_name, TOKEN_LIKE_PATTERNS)) or (
            func is not None and name_matches_patterns(func.name, TOKEN_LIKE_PATTERNS)
        )
        if matched:
            findings.append(_make_finding(context, node.lineno, info, "weak randomness used for a security token"))
    return findings


def _mentions_pattern(node, patterns):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and name_matches_patterns(sub.id, patterns):
            return True
        if isinstance(sub, ast.Attribute) and name_matches_patterns(sub.attr, patterns):
            return True
    return False


def _enclosing_assign_name(node, parent_map):
    current = parent_map.get(node)
    while current is not None:
        if isinstance(current, ast.Assign) and len(current.targets) == 1 and isinstance(current.targets[0], ast.Name):
            return current.targets[0].id
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module, ast.ClassDef)):
            return None
        current = parent_map.get(current)
    return None


def _make_finding(context, line, info, message):
    return Finding(
        rule=info.rule,
        cwe=info.cwe,
        severity=Severity(info.severity),
        path=context.path,
        line=line,
        message=message,
    )
