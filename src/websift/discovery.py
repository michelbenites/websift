"""Walks a project folder and finds the Python files to scan.

Only files ending in .py are returned. Folders listed in
config.SKIPPED_FOLDERS are not descended into. Symlinks are never
followed, for directories or files. The returned paths are built by
joining the given root with each file's relative location, using
forward slashes, so output looks the same on every platform.
"""

import os

from .config import SKIPPED_FOLDERS

_SKIPPED_LOWER = {name.lower() for name in SKIPPED_FOLDERS}


def discover_python_files(root):
    """Return a sorted list of .py file paths found under root."""
    results = []
    for current_dir, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if not _is_skipped_folder(name))
        rel_dir = os.path.relpath(current_dir, root)
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            full_path = os.path.join(current_dir, filename)
            if os.path.islink(full_path):
                continue
            results.append(_build_display_path(root, rel_dir, filename))
    return sorted(results)


def _is_skipped_folder(name):
    # Compared case-insensitively since Windows file systems treat
    # ".venv" and ".VENV" as the same folder.
    return name.lower() in _SKIPPED_LOWER


def is_folder(path):
    return os.path.isdir(path)


def _build_display_path(root, rel_dir, filename):
    root_norm = _to_forward_slashes(root)
    if rel_dir in (".", ""):
        return _join(root_norm, filename)
    rel_norm = _to_forward_slashes(rel_dir)
    return _join(_join(root_norm, rel_norm), filename)


def _to_forward_slashes(path):
    return path.replace("\\", "/")


def _join(first, second):
    if first.endswith("/"):
        return first + second
    return first + "/" + second


def read_source(path):
    """Read a file's text as utf-8, replacing any invalid bytes.

    utf-8-sig also strips a leading byte order mark, which editors on
    Windows sometimes add and which would otherwise land inside the
    first token when the source is parsed.
    """
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        return handle.read()
