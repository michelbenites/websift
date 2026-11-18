import os

from conftest import write_file
from websift.discovery import discover_python_files, is_folder, read_source


def test_discover_finds_py_files(tmp_path):
    write_file(tmp_path, "a.py", "x = 1\n")
    write_file(tmp_path, "b.py", "y = 2\n")
    write_file(tmp_path, "notes.txt", "hello\n")

    found = discover_python_files(str(tmp_path))

    assert len(found) == 2
    assert all(f.endswith(".py") for f in found)


def test_discover_uses_forward_slashes(tmp_path):
    write_file(tmp_path, "pkg/mod.py", "x = 1\n")

    found = discover_python_files(str(tmp_path))

    assert len(found) == 1
    assert "\\" not in found[0]
    assert found[0].endswith("pkg/mod.py")


def test_discover_sorted_by_path(tmp_path):
    write_file(tmp_path, "z.py", "x = 1\n")
    write_file(tmp_path, "a.py", "x = 1\n")
    write_file(tmp_path, "m/b.py", "x = 1\n")

    found = discover_python_files(str(tmp_path))

    assert found == sorted(found)


def test_discover_skips_configured_folders(tmp_path):
    write_file(tmp_path, "keep.py", "x = 1\n")
    write_file(tmp_path, ".venv/skip.py", "x = 1\n")
    write_file(tmp_path, "__pycache__/skip.py", "x = 1\n")
    write_file(tmp_path, "node_modules/skip.py", "x = 1\n")
    write_file(tmp_path, "build/skip.py", "x = 1\n")
    write_file(tmp_path, "dist/skip.py", "x = 1\n")
    write_file(tmp_path, ".git/skip.py", "x = 1\n")

    found = discover_python_files(str(tmp_path))

    assert len(found) == 1
    assert found[0].endswith("keep.py")


def test_discover_skips_folders_case_insensitively(tmp_path):
    write_file(tmp_path, "keep.py", "x = 1\n")
    write_file(tmp_path, "BUILD/skip.py", "x = 1\n")

    found = discover_python_files(str(tmp_path))

    assert len(found) == 1
    assert found[0].endswith("keep.py")


def test_discover_empty_folder(tmp_path):
    assert discover_python_files(str(tmp_path)) == []


def test_discover_nested_folders(tmp_path):
    write_file(tmp_path, "a/b/c/deep.py", "x = 1\n")

    found = discover_python_files(str(tmp_path))

    assert len(found) == 1
    assert found[0].endswith("a/b/c/deep.py")


def test_is_folder_true_for_directory(tmp_path):
    assert is_folder(str(tmp_path)) is True


def test_is_folder_false_for_file_or_missing_path(tmp_path):
    file_path = write_file(tmp_path, "a.py", "x = 1\n")
    assert is_folder(file_path) is False
    assert is_folder(str(tmp_path / "nope")) is False


def test_read_source_basic(tmp_path):
    path = write_file(tmp_path, "a.py", "x = 1\n")
    assert read_source(path) == "x = 1\n"


def test_read_source_strips_bom(tmp_path):
    path = tmp_path / "bom.py"
    path.write_bytes(b"\xef\xbb\xbfx = 1\n")
    source = read_source(str(path))
    assert source == "x = 1\n"
    assert not source.startswith("﻿")


def test_read_source_replaces_invalid_bytes(tmp_path):
    path = tmp_path / "bad.py"
    path.write_bytes(b"x = 1  # \xff\xfe broken\n")
    source = read_source(str(path))
    assert "x = 1" in source
