"""Utility endpoints for the clean sample shop."""

import json
import subprocess

from flask import Blueprint, request

tools_bp = Blueprint("tools", __name__)

_ALLOWED_OPS = {"add", "subtract", "multiply"}


@tools_bp.route("/calc")
def calc():
    op = request.args.get("op", "add")
    if op not in _ALLOWED_OPS:
        return {"error": "unknown operation"}
    a = float(request.args.get("a", "0"))
    b = float(request.args.get("b", "0"))
    if op == "add":
        result = a + b
    elif op == "subtract":
        result = a - b
    else:
        result = a * b
    return {"result": result}


@tools_bp.route("/convert")
def convert():
    name = request.args.get("name", "")
    subprocess.run(["convert", name, "out.png"])
    return {"status": "ok"}


@tools_bp.route("/load")
def load():
    obj = json.loads(request.data)
    return {"loaded": obj}
