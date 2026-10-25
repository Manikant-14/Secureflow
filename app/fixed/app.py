"""
SecureFlow demo target - HARDENED version.

Same features as ../vulnerable/app.py, with every flaw fixed.
"""
import os
import secrets
import sqlite3

import yaml
from flask import Flask, abort, jsonify, make_response, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # reject oversized bodies

# Secrets come from the environment, never from source code.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ALLOWED_ORIGINS = {
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "https://app.example.com").split(",") if o.strip()
}
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD") or secrets.token_urlsafe(12)

db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript(
    """
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT);
    INSERT INTO products (name) VALUES ('laptop'), ('keyboard'), ('monitor');
    """
)
for name, mail in [("alice", "alice@example.com"), ("bob", "bob@example.com")]:
    db.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (name, generate_password_hash(DEMO_PASSWORD), mail),
    )
db.commit()

SESSIONS = {}  # session token -> user id


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.vary.add("Origin")
    # CORS: only allow-listed origins are echoed back.
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/")
def index():
    resp = make_response(render_template("index.html"))
    resp.set_cookie("session_id", secrets.token_urlsafe(16), secure=True, httponly=True, samesite="Strict")
    return resp


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/search")
def search():
    q = request.args.get("q", "")[:100]
    # Parameterised query: user input is never part of the SQL text.
    rows = db.execute("SELECT id, name FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    # Jinja2 auto-escapes q and the product names.
    return render_template("search.html", q=q, rows=rows)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    row = db.execute("SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
    if row and check_password_hash(row[1], password):
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = row[0]
        resp = jsonify(status="ok", user_id=row[0])
        resp.set_cookie("session_id", token, secure=True, httponly=True, samesite="Strict")
        return resp
    return jsonify(status="invalid"), 401


@app.route("/config", methods=["POST"])
def config():
    try:
        data = yaml.safe_load(request.get_data(as_text=True))  # safe_load only builds plain data types
    except yaml.YAMLError:
        return jsonify(error="invalid YAML"), 400
    return jsonify(loaded=str(data))


@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    current = SESSIONS.get(request.cookies.get("session_id", ""))
    if current is None:
        abort(401)
    if current != user_id:  # object-level authorisation: you may only read your own record
        abort(403)
    row = db.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(id=row[0], username=row[1], email=row[2])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
