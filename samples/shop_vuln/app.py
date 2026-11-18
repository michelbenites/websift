"""Flask routes for the vulnerable sample shop.

This file plants several real security problems on purpose, for
websift to find. It is never run, only read.
"""

import requests
from flask import Flask, make_response, redirect, render_template_string, request, send_file, url_for
from flask_cors import CORS

from . import db

app = Flask(__name__)
CORS(app, origins="*")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = db.get_connection()
    cursor = conn.cursor()
    sql = f"SELECT id, name FROM products WHERE name LIKE '%{q}%'"
    cursor.execute(sql)
    return {"results": cursor.fetchall()}


@app.route("/product")
def product():
    pid = request.args["id"]
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = " + pid)
    return {"product": cursor.fetchone()}


@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("name", "")
    pw = request.form.get("pw", "")
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id FROM users WHERE name = '{name}' AND pw = '{pw}'")  # nosec PY-HASH
    user = cursor.fetchone()
    if user:
        return redirect(url_for("index"))
    return {"error": "invalid credentials"}


@app.route("/orders")
def orders():
    uid = request.json.get("user_id")
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id = %s" % uid)  # nosec PY-SQL
    return {"orders": cursor.fetchall()}


@app.route("/stats")
def stats():
    table = "products"
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    return {"count": cursor.fetchone()}


@app.route("/cart")
def cart():
    cart_id = request.args.get("cart_id", "")
    resp = make_response({"cart_id": cart_id})
    resp.set_cookie("cart_id", cart_id)
    return resp


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<p>Hello " + name + "</p>")


@app.route("/download")
def download():
    return send_file(request.args["file"])


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text


@app.route("/go-next")
def go_next():
    return redirect(request.args.get("next"))


@app.route("/index")
def index():
    return "welcome to the shop"


app.run(debug=True)  # nosec
