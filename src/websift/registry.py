"""Rule registry: a decorator to register rules, and the runner that
calls every registered rule against one parsed file.

Rule modules are not imported here, to avoid a circular import; the
caller (the rules package, or tests) is responsible for importing the
rule modules so their decorators run before run_rules is used.
"""

import ast

from . import pyast
from .model import Finding

_RULES = []


def rule(func):
    """Register a rule function.

    Each rule takes a Context and returns an iterable of Finding
    objects for the file in that context.
    """
    _RULES.append(func)
    return func


def registered_rules():
    """Return the list of currently registered rule functions."""
    return list(_RULES)


def registered_rule_count():
    return len(_RULES)


def clear_rules():
    """Remove all registered rules. Used by tests that need isolation."""
    _RULES.clear()


def snapshot_rules():
    """Capture the current rule list, to restore later with
    restore_rules. Lets a test register a throwaway rule without
    leaking it into every other test in the session."""
    return list(_RULES)


def restore_rules(snapshot):
    _RULES.clear()
    _RULES.extend(snapshot)


class Context:
    """Data shared by every rule when scanning a single file."""

    def __init__(self, path, tree):
        self.path = path
        self.tree = tree
        self.parent_map = pyast.build_parent_map(tree)
        self.import_map = pyast.build_import_map(tree)


def parse_source(path, source):
    """Parse source into an ast tree.

    Returns (tree, error_message). error_message is None on success,
    or the SyntaxError text when parsing fails.
    """
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return None, str(exc)
    return tree, None


def run_rules(path, source):
    """Parse source and run every registered rule against it.

    Returns (findings, error_message), where error_message is set
    instead of findings when the file has a syntax error.
    """
    tree, error = parse_source(path, source)
    if error is not None:
        return [], error

    context = Context(path, tree)
    findings = []
    for rule_func in _RULES:
        findings.extend(_run_one_rule(rule_func, context))
    return findings, None


def _run_one_rule(rule_func, context):
    """Run one rule and make sure it only hands back real Findings.

    A rule that returns something else is a bug in that rule, and
    should fail loudly here instead of corrupting the report.
    """
    results = list(rule_func(context))
    for result in results:
        if not isinstance(result, Finding):
            raise TypeError(rule_func.__name__ + " returned a non-Finding result")
    return results
