"""Database helpers for the clean sample shop.

Every query is either a fixed string or uses ? placeholders with the
values passed separately, so none of this file should ever trigger a
finding.
"""

import sqlite3

DB_PATH = "shop.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, pw_hash TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL)")
    conn.commit()
    conn.close()


def seed_products(conn):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO products (name, price) VALUES (?, ?)", ("Widget", 9.99))
    cursor.execute("INSERT INTO products (name, price) VALUES (?, ?)", ("Gadget", 19.99))
    conn.commit()


def count_products(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM products")
    return cursor.fetchone()[0]
