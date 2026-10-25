"""
SecureFlow demo target - INTENTIONALLY VULNERABLE.

Every flaw in this file is deliberate, so the pipeline has something to catch.
Never deploy this app anywhere that is reachable from the internet.
"""
import hashlib
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

# FLAW: hard-coded secrets (fake values, demo only)
app.secret_key = "super-secret-key-123"
API_KEY = "x9Fq2LmZ7pRt4VbN8cYd1HsK6wJe3GaU"

db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript(
    """
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT);
    INSERT INTO products (name) VALUES ('laptop'), ('keyboard'), ('monitor');
    """
)
for name, pw, mail in [("alice", "alice123", "alice@example.com"), ("bob", "bob456", "bob@example.com")]:
    # FLAW: MD5 for password hashing
    db.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (name, hashlib.md5(pw.encode()).hexdigest(), mail),
    )
db.commit()


@app.after_request
def add_headers(resp):
    origin = request.headers.get("Origin")
    if origin:
        # FLAW: reflects any Origin and allows credentials
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    # FLAW: leaks framework and runtime versions
    resp.headers["X-Powered-By"] = "Flask/2.0.1 Python/3.8"
    # FLAW: no CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, ...
    return resp


@app.route("/")
def index():
    resp = make_response("<h1>SecureFlow demo shop</h1><p>Try /search?q=laptop</p>")
    # FLAW: session cookie without Secure, HttpOnly or SameSite
    resp.set_cookie("session_id", "abc123")
    return resp


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # FLAW: SQL injection (string concatenation)
    query = "SELECT id, name FROM products WHERE name LIKE '%" + q + "%'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as exc:
        # FLAW: verbose error leaks the query
        return f"<pre>SQL error: {exc}\nQuery: {query}</pre>", 500
    # FLAW: reflected XSS (user input placed into HTML unescaped)
    items = "".join(f"<li>{row[1]}</li>" for row in rows)
    return f"<h2>Results for {q}</h2><ul>{items}</ul>"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = hashlib.md5(request.form.get("password", "").encode()).hexdigest()
    # FLAW: SQL injection in authentication
    sql = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    row = db.execute(sql).fetchone()
    if row:
        return jsonify(status="ok", user_id=row[0])
    return jsonify(status="invalid"), 401


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FLAW: OS command injection (shell=True with user input)
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)
    return "<pre>" + out.stdout + "</pre>"


@app.route("/config", methods=["POST"])
def config():
    # FLAW: unsafe YAML deserialisation
    data = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(loaded=str(data))


@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    # FLAW: Broken Object Level Authorization - no authentication or ownership check
    row = db.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(id=row[0], username=row[1], email=row[2])


@app.route("/.env")
def dotenv():
    # FLAW: sensitive file exposed over HTTP
    return "DB_PASSWORD=hunter2\nAPP_ENV=production\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    # FLAW: debug mode and binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
