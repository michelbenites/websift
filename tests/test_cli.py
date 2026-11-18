import subprocess
import sys
from pathlib import Path

from conftest import write_file
from websift.cli import main

_WS_PY = Path(__file__).resolve().parent.parent / "ws.py"


def test_scan_clean_project_exits_zero(tmp_path, capsys):
    write_file(tmp_path, "app.py", "x = 1\n")

    code = main(["scan", str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 0
    assert "Summary: 0 findings (0 high, 0 medium, 0 low)" in out


def test_scan_vulnerable_project_exits_one(tmp_path, capsys):
    write_file(tmp_path, "app.py", 'import pickle\npickle.loads(data)\n')

    code = main(["scan", str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 1
    assert "PY-PICKLE" in out
    assert "Summary: 1 findings (1 high, 0 medium, 0 low)" in out


def test_scan_reports_multiple_findings_sorted(tmp_path, capsys):
    write_file(tmp_path, "b.py", "eval(x)\n")
    write_file(tmp_path, "a.py", "eval(x)\n")

    code = main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if "PY-EVAL" in line]

    assert code == 1
    assert len(lines) == 2
    assert "a.py" in lines[0]
    assert "b.py" in lines[1]


def test_scan_skips_syntax_error_file_with_warning(tmp_path, capsys):
    write_file(tmp_path, "broken.py", "def f(:\n")
    write_file(tmp_path, "ok.py", "eval(x)\n")

    code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()

    assert code == 1
    assert "PY-EVAL" in captured.out
    assert "warning: skipping" in captured.err
    assert "broken.py" in captured.err


def test_scan_missing_path_is_usage_error(capsys):
    code = main(["scan"])
    err = capsys.readouterr().err

    assert code == 2
    assert err.strip() != ""


def test_scan_not_a_folder_is_usage_error(tmp_path, capsys):
    file_path = write_file(tmp_path, "a.py", "x = 1\n")

    code = main(["scan", file_path])
    err = capsys.readouterr().err

    assert code == 2
    assert "not a folder" in err


def test_no_command_is_usage_error(capsys):
    code = main([])
    err = capsys.readouterr().err

    assert code == 2
    assert err.strip() != ""


def test_unknown_command_is_usage_error(capsys):
    code = main(["frobnicate", "somewhere"])
    err = capsys.readouterr().err

    assert code == 2
    assert err.strip() != ""


def test_scan_missing_folder_is_usage_error(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"

    code = main(["scan", str(missing)])
    err = capsys.readouterr().err

    assert code == 2
    assert "not a folder" in err


def test_main_defaults_to_sys_argv(tmp_path, monkeypatch, capsys):
    write_file(tmp_path, "app.py", "x = 1\n")
    monkeypatch.setattr(sys, "argv", ["ws.py", "scan", str(tmp_path)])

    code = main()
    out = capsys.readouterr().out

    assert code == 0
    assert "Summary: 0 findings" in out


def test_cli_via_subprocess_clean_project(tmp_path):
    write_file(tmp_path, "app.py", "x = 1\n")

    result = subprocess.run(
        [sys.executable, str(_WS_PY), "scan", str(tmp_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Summary: 0 findings (0 high, 0 medium, 0 low)" in result.stdout


def test_cli_via_subprocess_vulnerable_project(tmp_path):
    write_file(tmp_path, "app.py", "eval(x)\n")

    result = subprocess.run(
        [sys.executable, str(_WS_PY), "scan", str(tmp_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "PY-EVAL" in result.stdout


def test_cli_via_subprocess_usage_error(tmp_path):
    missing = tmp_path / "nope"

    result = subprocess.run(
        [sys.executable, str(_WS_PY), "scan", str(missing)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert result.stderr.strip() != ""
