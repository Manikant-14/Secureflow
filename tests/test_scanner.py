from scanner import webscan


def ids(findings):
    return {f["rule_id"] for f in findings}


def test_header_rules_flag_missing_headers():
    found = webscan.check_headers({}, "http://localhost:5000")
    assert {"SF-HDR-001", "SF-HDR-003", "SF-HDR-004", "SF-HDR-005", "SF-HDR-006"} <= ids(found)
    assert "SF-HDR-007" not in ids(found)  # HSTS only applies to HTTPS


def test_hsts_checked_on_https_only():
    assert "SF-HDR-007" in ids(webscan.check_headers({}, "https://example.com"))


def test_good_headers_are_clean():
    good = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()", "Server": "gunicorn",
    }
    assert webscan.check_headers(good, "http://localhost") == []


def test_weak_csp_and_version_disclosure():
    found = webscan.check_headers({"Content-Security-Policy": "script-src 'unsafe-inline'", "Server": "nginx/1.18.0"}, "http://x")
    assert "SF-HDR-002" in ids(found) and "SF-INFO-001" in ids(found)


def test_cookie_flags():
    bad = webscan.check_cookies(["session_id=abc123; Path=/"], "http://x")
    assert ids(bad) == {"SF-COOKIE-001", "SF-COOKIE-002", "SF-COOKIE-003"}
    good = webscan.check_cookies(["session_id=abc; Secure; HttpOnly; SameSite=Strict; Path=/"], "http://x")
    assert good == []


def test_vulnerable_app_is_flagged(vulnerable_url):
    found = webscan.scan(vulnerable_url)
    assert {"SF-HDR-001", "SF-COOKIE-001", "SF-COOKIE-002", "SF-CORS-002", "SF-EXPOSE-001"} <= ids(found)
    cors = next(f for f in found if f["rule_id"] == "SF-CORS-002")
    assert cors["severity"] == "high"


def test_fixed_app_has_no_medium_or_worse(fixed_url):
    found = webscan.scan(fixed_url)
    assert [f for f in found if f["severity"] in ("medium", "high", "critical")] == []


def test_cli_refuses_remote_targets(capsys):
    assert webscan.main(["--url", "http://example.com", "--output", "x.json"]) == 2
