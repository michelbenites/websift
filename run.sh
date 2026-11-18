#!/usr/bin/env bash
set -e

PYTHON=python3
python3 --version >/dev/null 2>&1 || PYTHON=python

"$PYTHON" -m venv .venv

if [ -f ".venv/bin/activate" ]; then
    . .venv/bin/activate
else
    . .venv/Scripts/activate
fi

pip install --quiet pytest

python -m pytest -q
