import ast

import pytest

from websift.pyast import (
    build_import_map,
    build_parent_map,
    dotted_name,
    enclosing_function,
    get_keyword,
    is_constant_string,
    is_dynamic_string,
    is_false_constant,
    is_true_constant,
    last_assignment_before,
    local_assignments,
    name_matches_patterns,
    resolve_call_name,
    resolve_dotted,
    string_literal_value,
)


def parse(source):
    return ast.parse(source)


def first_call(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            return node
    raise AssertionError("no call found")


def test_build_parent_map_links_child_to_parent():
    tree = parse("x = 1\n")
    parents = build_parent_map(tree)
    assign = tree.body[0]
    assert parents[assign.targets[0]] is assign


def test_dotted_name_simple_name():
    tree = parse("x\n")
    expr = tree.body[0].value
    assert dotted_name(expr) == "x"


def test_dotted_name_attribute_chain():
    tree = parse("a.b.c\n")
    expr = tree.body[0].value
    assert dotted_name(expr) == "a.b.c"


def test_dotted_name_none_for_call_base():
    tree = parse("f().attr\n")
    expr = tree.body[0].value
    assert dotted_name(expr) is None


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import pickle\n", {}),
        ("import pickle as pk\n", {"pk": "pickle"}),
        ("from pickle import loads\n", {"loads": "pickle.loads"}),
        ("from pickle import loads as pl\n", {"pl": "pickle.loads"}),
        ("import os.path\n", {}),
        ("from . import something\n", {}),
    ],
)
def test_build_import_map(source, expected):
    tree = parse(source)
    assert build_import_map(tree) == expected


def test_resolve_dotted_with_alias():
    import_map = {"pk": "pickle"}
    assert resolve_dotted("pk.loads", import_map) == "pickle.loads"


def test_resolve_dotted_bare_from_import():
    import_map = {"loads": "pickle.loads"}
    assert resolve_dotted("loads", import_map) == "pickle.loads"


def test_resolve_dotted_no_match_passthrough():
    assert resolve_dotted("hashlib.md5", {}) == "hashlib.md5"


def test_resolve_dotted_none_input():
    assert resolve_dotted(None, {}) is None


def test_resolve_call_name_uses_import_map():
    tree = parse("import pickle as pk\npk.loads(data)\n")
    call = first_call(tree)
    import_map = build_import_map(tree)
    assert resolve_call_name(call, import_map) == "pickle.loads"


def test_is_constant_string_true():
    tree = parse('"hello"\n')
    assert is_constant_string(tree.body[0].value) is True


def test_is_constant_string_false_for_fstring():
    tree = parse('f"hello {x}"\n')
    assert is_constant_string(tree.body[0].value) is False


def test_string_literal_value():
    tree = parse('"abc"\n')
    assert string_literal_value(tree.body[0].value) == "abc"


def test_string_literal_value_none_for_number():
    tree = parse("123\n")
    assert string_literal_value(tree.body[0].value) is None


@pytest.mark.parametrize(
    "source,expected",
    [
        ('f"{x}"\n', True),
        ('"a" + x\n', True),
        ('"a %s" % x\n', True),
        ('"a {}".format(x)\n', True),
        ('"plain"\n', False),
        ("123\n", False),
        ('f"no placeholder"\n', False),
    ],
)
def test_is_dynamic_string_expressions(source, expected):
    tree = parse(source)
    assert is_dynamic_string(tree.body[0].value) is expected


def test_is_dynamic_string_for_aug_assign():
    tree = parse("sql = 'a'\nsql += x\n")
    aug = tree.body[1]
    assert is_dynamic_string(aug) is True


def test_get_keyword_found():
    tree = parse("f(a=1, b=2)\n")
    call = first_call(tree)
    value = get_keyword(call, "b")
    assert isinstance(value, ast.Constant)
    assert value.value == 2


def test_get_keyword_missing():
    tree = parse("f(a=1)\n")
    call = first_call(tree)
    assert get_keyword(call, "shell") is None


def test_is_true_constant():
    tree = parse("True\n")
    assert is_true_constant(tree.body[0].value) is True


def test_is_true_constant_false_for_other_values():
    tree = parse("1\n")
    assert is_true_constant(tree.body[0].value) is False


def test_is_false_constant():
    tree = parse("False\n")
    assert is_false_constant(tree.body[0].value) is True


@pytest.mark.parametrize(
    "name,patterns,expected",
    [
        ("API_TOKEN", ("token",), True),
        ("api_token", ("token",), True),
        ("username", ("token",), False),
        (None, ("token",), False),
        ("", ("token",), False),
    ],
)
def test_name_matches_patterns(name, patterns, expected):
    assert name_matches_patterns(name, patterns) is expected


def test_enclosing_function_found():
    tree = parse("def f():\n    x = 1\n")
    parents = build_parent_map(tree)
    inner = tree.body[0].body[0]
    func = enclosing_function(inner, parents)
    assert func is tree.body[0]


def test_enclosing_function_none_at_module_level():
    tree = parse("x = 1\n")
    parents = build_parent_map(tree)
    assert enclosing_function(tree.body[0], parents) is None


def test_enclosing_function_nested():
    tree = parse("def outer():\n    def inner():\n        y = 1\n    return inner\n")
    parents = build_parent_map(tree)
    inner_func = tree.body[0].body[0]
    inner_assign = inner_func.body[0]
    assert enclosing_function(inner_assign, parents) is inner_func


def test_local_assignments_tracks_order():
    tree = parse("def f():\n    x = 1\n    x = 2\n")
    func = tree.body[0]
    assignments = local_assignments(func)
    lines = [ln for ln, _ in assignments["x"]]
    assert lines == [2, 3]


def test_local_assignments_skips_nested_function():
    tree = parse("def f():\n    def g():\n        x = 1\n    x = 2\n")
    func = tree.body[0]
    assignments = local_assignments(func)
    assert len(assignments["x"]) == 1
    assert assignments["x"][0][0] == 4


def test_local_assignments_includes_aug_assign():
    tree = parse("def f():\n    x = 'a'\n    x += 'b'\n")
    func = tree.body[0]
    assignments = local_assignments(func)
    assert [ln for ln, _ in assignments["x"]] == [2, 3]


def test_local_assignments_ignores_tuple_targets():
    tree = parse("def f():\n    a, b = 1, 2\n")
    func = tree.body[0]
    assignments = local_assignments(func)
    assert assignments == {}


def test_last_assignment_before_picks_latest_eligible():
    tree = parse("def f():\n    x = 1\n    x = 2\n    x = 3\n")
    func = tree.body[0]
    assignments = local_assignments(func)
    value = last_assignment_before(assignments, "x", 3)
    assert value.value == 2


def test_last_assignment_before_no_match():
    assignments = {"x": [(5, ast.Constant(value=1))]}
    assert last_assignment_before(assignments, "x", 2) is None
    assert last_assignment_before({}, "missing", 10) is None
