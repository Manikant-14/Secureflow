"""Proof that the vulnerable app really is vulnerable and the fixed app really is fixed."""
UNION = "zzz' UNION SELECT id, username FROM users--"
XSS = "<script>alert(1)</script>"


def test_sql_injection_works_on_vulnerable(vulnerable_app):
    body = vulnerable_app.test_client().get("/search", query_string={"q": UNION}).get_data(as_text=True)
    assert "alice" in body  # data from another table leaked


def test_sql_injection_blocked_on_fixed(fixed_app):
    body = fixed_app.test_client().get("/search", query_string={"q": UNION}).get_data(as_text=True)
    assert "alice" not in body


def test_xss_reflected_on_vulnerable(vulnerable_app):
    body = vulnerable_app.test_client().get("/search", query_string={"q": XSS}).get_data(as_text=True)
    assert XSS in body


def test_xss_escaped_on_fixed(fixed_app):
    body = fixed_app.test_client().get("/search", query_string={"q": XSS}).get_data(as_text=True)
    assert XSS not in body and "&lt;script&gt;" in body


def test_unsafe_yaml_on_vulnerable(vulnerable_app):
    resp = vulnerable_app.test_client().post("/config", data="!!python/tuple [1, 2]")
    assert resp.status_code == 200 and "(1, 2)" in resp.get_data(as_text=True)


def test_unsafe_yaml_rejected_on_fixed(fixed_app):
    resp = fixed_app.test_client().post("/config", data="!!python/tuple [1, 2]")
    assert resp.status_code == 400


def test_bola_on_vulnerable(vulnerable_app):
    assert vulnerable_app.test_client().get("/api/users/1").status_code == 200


def test_bola_blocked_on_fixed(fixed_app):
    client = fixed_app.test_client()
    assert client.get("/api/users/1").status_code == 401


def test_fixed_user_cannot_read_other_users(fixed_app):
    import importlib
    module = importlib.import_module("fixed_app")
    client = fixed_app.test_client()
    # Log in as alice (id 1) using the generated demo password.
    resp = client.post("/login", data={"username": "alice", "password": module.DEMO_PASSWORD})
    assert resp.status_code == 200
    client.set_cookie("session_id", resp.headers["Set-Cookie"].split("session_id=")[1].split(";")[0])
    assert client.get("/api/users/1").status_code == 200
    assert client.get("/api/users/2").status_code == 403


def test_cors_reflection(vulnerable_app, fixed_app):
    evil = {"Origin": "https://evil.example"}
    assert vulnerable_app.test_client().get("/", headers=evil).headers.get("Access-Control-Allow-Origin") == "https://evil.example"
    assert "Access-Control-Allow-Origin" not in fixed_app.test_client().get("/", headers=evil).headers


def test_security_headers(vulnerable_app, fixed_app):
    assert "Content-Security-Policy" not in vulnerable_app.test_client().get("/").headers
    fixed = fixed_app.test_client().get("/").headers
    for name in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
        assert name in fixed
