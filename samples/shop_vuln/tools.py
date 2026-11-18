"""Utility endpoints for the vulnerable sample shop."""

import pickle
import subprocess

from flask import Blueprint, request

tools_bp = Blueprint("tools", __name__)


@tools_bp.route("/calc")
def calc():
    expr = request.args.get("expr", "1")
    result = eval(expr)
    return {"result": result}


@tools_bp.route("/convert")
def convert():
    name = request.args.get("name", "")
    subprocess.run("convert " + name + " out.png", shell=True)
    return {"status": "ok"}


@tools_bp.route("/load")
def load():
    obj = pickle.loads(request.data)
    return {"loaded": str(obj)}
