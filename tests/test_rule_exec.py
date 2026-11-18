import pytest

from conftest import findings_for


def eval_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-EVAL"]


def shell_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-SHELL"]


def pickle_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-PICKLE"]


@pytest.mark.parametrize(
    "source",
    [
        "eval(expr)\n",
        "exec(code)\n",
        "eval(user_input + '1')\n",
        "import builtins\nbuiltins.eval(expr)\n",
    ],
)
def test_eval_exec_non_constant_flagged(source):
    findings = eval_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 95
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    "source",
    [
        'eval("1 + 1")\n',
        'exec("x = 1")\n',
        "import ast\nast.literal_eval(expr)\n",
        "eval()\n",
    ],
)
def test_eval_exec_constant_or_literal_eval_not_flagged(source):
    assert eval_findings(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(cmd, shell=True)\n",
        "import subprocess\nsubprocess.call(cmd, shell=True)\n",
        "import subprocess\nsubprocess.Popen(cmd, shell=True)\n",
        "import subprocess\nsubprocess.check_call(cmd, shell=True)\n",
        "import subprocess\nsubprocess.check_output(cmd, shell=True)\n",
        "from subprocess import run\nrun(cmd, shell=True)\n",
        "import subprocess as sp\nsp.run(cmd, shell=True)\n",
    ],
)
def test_subprocess_shell_true_flagged(source):
    findings = shell_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 78
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(cmd)\n",
        "import subprocess\nsubprocess.run(cmd, shell=False)\n",
        "import subprocess\nsubprocess.run(['ls', '-l'])\n",
    ],
)
def test_subprocess_without_shell_true_not_flagged(source):
    assert shell_findings(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "import pickle\npickle.load(f)\n",
        "import pickle\npickle.loads(data)\n",
        "import pickle as pk\npk.loads(data)\n",
        "from pickle import loads\nloads(data)\n",
        "from pickle import load as pickle_load\npickle_load(f)\n",
    ],
)
def test_pickle_load_flagged(source):
    findings = pickle_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 502
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    "source",
    [
        "import json\njson.loads(data)\n",
        "import pickle\npickle.dump(obj, f)\n",
        "import pickle\npickle.dumps(obj)\n",
    ],
)
def test_pickle_dump_and_other_formats_not_flagged(source):
    assert pickle_findings(source) == []
