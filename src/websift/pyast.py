"""Generic ast helpers shared by the rules.

Covers: a parent map for walking upward, dotted name extraction,
import alias resolution (so `import pickle as pk` and
`from pickle import loads` both resolve back to `pickle.loads`),
constant and dynamic string checks, finding the enclosing function,
and collecting a function's local name assignments.
"""

import ast


def build_parent_map(tree):
    """Map every node in tree to its parent node."""
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def enclosing_function(node, parent_map):
    """Return the nearest enclosing FunctionDef/AsyncFunctionDef, or None."""
    current = parent_map.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parent_map.get(current)
    return None


def dotted_name(node):
    """Return the dotted name of a Name/Attribute chain, or None.

    `pickle.loads` -> "pickle.loads", a bare Name -> its id, anything
    with a non-name base (a call, a subscript, ...) -> None.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        if base is None:
            return None
        return base + "." + node.attr
    return None


def build_import_map(tree):
    """Map local names to the fully qualified dotted name they refer to.

    Only entries that differ from a plain lookup are needed: aliased
    imports and from-imports. A plain `import os` is not included,
    since dotted_name already yields "os" for it.
    """
    import_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    import_map[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.level:
                continue
            for alias in node.names:
                local = alias.asname or alias.name
                import_map[local] = node.module + "." + alias.name
    return import_map


def resolve_dotted(dotted, import_map):
    """Resolve the leading component of a dotted name through import_map."""
    if dotted is None:
        return None
    parts = dotted.split(".")
    head = parts[0]
    if head in import_map:
        resolved_head = import_map[head]
        rest = parts[1:]
        if rest:
            return resolved_head + "." + ".".join(rest)
        return resolved_head
    return dotted


def resolve_call_name(call_node, import_map):
    """Resolve the fully qualified dotted name of a call's target."""
    return resolve_dotted(dotted_name(call_node.func), import_map)


def is_constant_string(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def string_literal_value(node):
    """Return the literal string value of a constant string, or None."""
    if is_constant_string(node):
        return node.value
    return None


def is_dynamic_string(node):
    """True for an f-string with interpolation, concatenation, % formatting,
    a call to .format(), or an in-place += build, the ways a query string
    gets built at runtime instead of staying a fixed constant."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
        return True
    return False


def get_keyword(call_node, name):
    """Return the value node of a keyword argument, or None."""
    for kw in call_node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_true_constant(node):
    return isinstance(node, ast.Constant) and node.value is True


def is_false_constant(node):
    return isinstance(node, ast.Constant) and node.value is False


def name_matches_patterns(name, patterns):
    """Case insensitive substring match against a list of patterns."""
    if not name:
        return False
    lowered = name.lower()
    return any(pattern in lowered for pattern in patterns)


def local_assignments(func_node):
    """Map each simple `name = value` assignment in a function's own
    scope to the list of (lineno, value_node) pairs, in source order.

    Nested functions and lambdas are not descended into, since their
    assignments belong to a different scope.
    """
    assignments = {}

    class _Collector(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            return

        def visit_AsyncFunctionDef(self, node):
            return

        def visit_Lambda(self, node):
            return

        def visit_Assign(self, node):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                assignments.setdefault(name, []).append((node.lineno, node.value))
            self.generic_visit(node)

        def visit_AugAssign(self, node):
            if isinstance(node.target, ast.Name):
                # Store the AugAssign node itself: is_dynamic_string knows
                # how to read a += build directly from it.
                assignments.setdefault(node.target.id, []).append((node.lineno, node))
            self.generic_visit(node)

    collector = _Collector()
    for stmt in func_node.body:
        collector.visit(stmt)
    return assignments


def last_assignment_before(assignments, name, lineno):
    """Return the value last assigned to name at or before lineno."""
    entries = assignments.get(name, [])
    eligible = [(ln, value) for ln, value in entries if ln <= lineno]
    if not eligible:
        return None
    eligible.sort(key=lambda pair: pair[0])
    return eligible[-1][1]
