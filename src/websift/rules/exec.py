"""PY-EVAL, PY-SHELL and PY-PICKLE: dangerous calls that run code,
spawn a shell, or deserialize untrusted data.

PY-EVAL fires for eval/exec called with anything other than a string
constant; ast.literal_eval is never reported. PY-SHELL fires for a
subprocess call made with shell=True. PY-PICKLE fires for pickle.load
or pickle.loads, including aliased and from-imports.
"""

import ast

from ..config import SUBPROCESS_FUNCTION_NAMES, rule_info
from ..model import Finding, Severity
from ..pyast import get_keyword, is_true_constant, is_constant_string, resolve_call_name
from ..registry import rule

_PICKLE_LOAD_NAMES = ("pickle.load", "pickle.loads")


def _is_eval_or_exec(resolved):
    if resolved in ("eval", "exec"):
        return True
    return resolved in ("builtins.eval", "builtins.exec")


@rule
def check_eval(context):
    info = rule_info("PY-EVAL")
    findings = []
    for node in ast.walk(context.tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = resolve_call_name(node, context.import_map)
        if not _is_eval_or_exec(resolved):
            continue
        if not node.args:
            continue
        if is_constant_string(node.args[0]):
            continue
        findings.append(_make_finding(context, node.lineno, info, resolved.split(".")[-1] + "() called with a non-constant argument"))
    return findings


@rule
def check_shell(context):
    info = rule_info("PY-SHELL")
    findings = []
    for node in ast.walk(context.tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = resolve_call_name(node, context.import_map)
        if resolved is None:
            continue
        parts = resolved.split(".")
        if parts[0] != "subprocess" or parts[-1] not in SUBPROCESS_FUNCTION_NAMES:
            continue
        shell_value = get_keyword(node, "shell")
        if shell_value is not None and is_true_constant(shell_value):
            findings.append(_make_finding(context, node.lineno, info, "subprocess call runs through a shell"))
    return findings


@rule
def check_pickle(context):
    info = rule_info("PY-PICKLE")
    findings = []
    for node in ast.walk(context.tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = resolve_call_name(node, context.import_map)
        if resolved in _PICKLE_LOAD_NAMES:
            findings.append(_make_finding(context, node.lineno, info, "pickle used to deserialize data"))
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
