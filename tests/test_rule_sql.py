import pytest

from conftest import findings_for


def sql_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-SQL"]


@pytest.mark.parametrize(
    "source",
    [
        'cur.execute(f"SELECT * FROM t WHERE id = {x}")\n',
        'cur.execute("SELECT * FROM t WHERE id = " + x)\n',
        'cur.execute("SELECT * FROM t WHERE id = %s" % x)\n',
        'cur.execute("SELECT * FROM t WHERE id = {}".format(x))\n',
        'cur.executemany(f"INSERT INTO t VALUES ({x})", rows)\n',
        'cur.executescript(f"DROP TABLE {name}")\n',
        'execute(f"SELECT * FROM t WHERE id = {x}")\n',
    ],
)
def test_direct_dynamic_string_flagged(source):
    findings = sql_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 89
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    "source",
    [
        'cur.execute("SELECT * FROM t WHERE id = 1")\n',
        'cur.execute("SELECT * FROM t WHERE id = ?", (x,))\n',
        'cur.execute("SELECT * FROM t WHERE id = ?", (f"{x}",))\n',
        "cur.execute(query)\n",
    ],
)
def test_constant_or_placeholder_not_flagged(source):
    assert sql_findings(source) == []


def test_bare_name_assigned_dynamic_string_in_same_function():
    source = (
        "def run(x):\n"
        "    sql = f'SELECT * FROM t WHERE id = {x}'\n"
        "    cur.execute(sql)\n"
    )
    findings = sql_findings(source)
    assert len(findings) == 1
    assert findings[0].line == 2


def test_bare_name_assigned_constant_not_flagged():
    source = (
        "def run(x):\n"
        "    sql = 'SELECT * FROM t'\n"
        "    cur.execute(sql)\n"
    )
    assert sql_findings(source) == []


def test_last_assignment_wins_dynamic_then_constant():
    source = (
        "def run(x):\n"
        "    sql = f'SELECT * FROM t WHERE id = {x}'\n"
        "    sql = 'SELECT * FROM t'\n"
        "    cur.execute(sql)\n"
    )
    assert sql_findings(source) == []


def test_last_assignment_wins_constant_then_dynamic():
    source = (
        "def run(x):\n"
        "    sql = 'SELECT * FROM t'\n"
        "    sql = f'SELECT * FROM t WHERE id = {x}'\n"
        "    cur.execute(sql)\n"
    )
    findings = sql_findings(source)
    assert len(findings) == 1
    assert findings[0].line == 3


def test_aug_assign_counts_as_dynamic():
    source = (
        "def run(x):\n"
        "    sql = 'SELECT * FROM t'\n"
        "    sql += x\n"
        "    cur.execute(sql)\n"
    )
    findings = sql_findings(source)
    assert len(findings) == 1
    assert findings[0].line == 3


def test_assignment_in_different_function_not_used():
    source = (
        "def build():\n"
        "    sql = f'SELECT * FROM t WHERE id = {x}'\n"
        "    return sql\n"
        "def run(sql):\n"
        "    cur.execute(sql)\n"
    )
    assert sql_findings(source) == []


def test_assignment_outside_any_function_not_used():
    source = "sql = f'SELECT * FROM t WHERE id = {x}'\ncur.execute(sql)\n"
    assert sql_findings(source) == []


def test_nested_function_assignment_is_local():
    source = (
        "def outer(x):\n"
        "    def inner():\n"
        "        sql = f'SELECT * FROM t WHERE id = {x}'\n"
        "        cur.execute(sql)\n"
        "    inner()\n"
    )
    findings = sql_findings(source)
    assert len(findings) == 1
    assert findings[0].line == 3


def test_only_first_argument_is_checked():
    source = 'cur.execute("SELECT * FROM t WHERE id = ?", f"{x}")\n'
    assert sql_findings(source) == []


def test_call_with_no_arguments_not_flagged():
    source = "cur.execute()\n"
    assert sql_findings(source) == []


def test_unrelated_method_name_not_flagged():
    source = 'cur.fetchall(f"SELECT * FROM t WHERE id = {x}")\n'
    assert sql_findings(source) == []


def test_multiple_calls_in_one_file_all_flagged():
    source = (
        'cur.execute(f"SELECT * FROM a WHERE id = {x}")\n'
        'cur.execute("SELECT * FROM b")\n'
        'cur.execute(f"SELECT * FROM c WHERE id = {y}")\n'
    )
    findings = sql_findings(source)
    assert len(findings) == 2
    assert [f.line for f in findings] == [1, 3]
