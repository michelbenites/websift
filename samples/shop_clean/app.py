"""Flask routes for the clean sample shop.

Same routes as the vulnerable sample, done the right way: every
query uses placeholders, secrets come from the environment, and
nothing here should ever trigger a finding.
"""

import requests
from flask import Flask, make_response, redirect, render_template_string, request, send_file, url_for
from flask_cors import CORS

from . import db, settings

app = Flask(__name__)
CORS(app, origins=["https://shop.example.test"])


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM products WHERE name LIKE ?", (f"%{q}%",))
    return {"results": cursor.fetchall()}


@app.route("/product")
def product():
    pid = request.args["id"]
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (pid,))
    return {"product": cursor.fetchone()}


@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("name", "")
    pw_hash = request.form.get("pw_hash", "")
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE name = ? AND pw_hash = ?", (name, pw_hash))
    user = cursor.fetchone()
    if user:
        return redirect(url_for("index"))
    return {"error": "invalid credentials"}


@app.route("/orders")
def orders():
    uid = request.json.get("user_id")
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id = ?", (uid,))
    return {"orders": cursor.fetchall()}


@app.route("/stats")
def stats():
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM products")
    return {"count": cursor.fetchone()}


@app.route("/cart")
def cart():
    cart_id = request.args.get("cart_id", "")
    resp = make_response({"cart_id": cart_id})
    resp.set_cookie("cart_id", cart_id, secure=True, httponly=True, samesite="Lax")
    return resp


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<p>Hello {{ name }}</p>", name=name)


@app.route("/download")
def download():
    return send_file(settings.PRODUCT_CATALOG_PATH)


@app.route("/fetch")
def fetch():
    return requests.get(settings.CATALOG_FEED_URL).text


@app.route("/go-next")
def go_next():
    return redirect(url_for("cart"))


@app.route("/index")
def index():
    return "welcome to the shop"


app.run(debug=False)
