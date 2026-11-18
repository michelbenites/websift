"""PY-SQL: a SQL query string built dynamically and handed to execute,
executemany or executescript.

Flags a call whose first argument is itself an f-string with a value,
a string concatenation, % formatting, a .format() call, or an
in-place += build. Also flags it when the first argument is a local
name whose last assignment before the call built the string the same
way: last assignment wins, so a safe string reassigned dynamically
later is still flagged, and a dynamic string reassigned to something
constant later is not. Constant strings, and placeholders with values
in the second argument, are never flagged, even when that second
argument is itself built with an f-string.

The execute-like call can be a method on any object (cursor.execute,
self.cursor.executemany, ...) or a bare name reached through a
from-import (`from sqlite3 import ...` style helpers that re-export
execute directly).
"""

import ast

from ..config import SQL_EXEC_METHODS, rule_info
from ..model import Finding, Severity
from ..pyast import enclosing_function, is_dynamic_string, local_assignments
from ..registry import rule


@rule
def check_sql(context):
    info = rule_info("PY-SQL")
    findings = []
    for node in ast.walk(context.tree):
        if not _is_sql_exec_call(node):
            continue
        if not node.args:
            continue

        finding = _check_call(context, node, node.args[0], info)
        if finding is not None:
            findings.append(finding)
    return findings


def _is_sql_exec_call(node):
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in SQL_EXEC_METHODS
    if isinstance(node.func, ast.Name):
        return node.func.id in SQL_EXEC_METHODS
    return False


def _check_call(context, call_node, first_arg, info):
    if is_dynamic_string(first_arg):
        return _make_finding(context, call_node.lineno, info)

    if isinstance(first_arg, ast.Name):
        return _check_via_local_assignment(context, call_node, first_arg.id, info)

    return None


def _check_via_local_assignment(context, call_node, name, info):
    func = enclosing_function(call_node, context.parent_map)
    if func is None:
        return None

    assignments = local_assignments(func)
    last = _last_assignment(assignments, name, call_node.lineno)
    if last is None:
        return None

    assign_line, value = last
    if is_dynamic_string(value):
        return _make_finding(context, assign_line, info)
    return None


def _last_assignment(assignments, name, before_lineno):
    """Return the (line, value) of the assignment to name that is in
    effect at before_lineno: the latest one at or before that line."""
    entries = assignments.get(name, [])
    eligible = [(ln, value) for ln, value in entries if ln <= before_lineno]
    if not eligible:
        return None
    eligible.sort(key=lambda pair: pair[0])
    return eligible[-1]


def _make_finding(context, line, info):
    return Finding(
        rule=info.rule,
        cwe=info.cwe,
        severity=Severity(info.severity),
        path=context.path,
        line=line,
        message="SQL query is built from a dynamically formatted string",
    )
