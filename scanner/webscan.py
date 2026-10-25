"""
SecureFlow web scanner.

A small, dependency-light scanner for the web-layer problems that code scanners
cannot see: missing security headers, weak CORS, insecure cookies, version
disclosure and exposed files. It sends a handful of ordinary GET requests.

Only scan systems you own or have written permission to test. By default the
CLI refuses anything that is not localhost.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 8
USER_AGENT = "SecureFlow-Scanner/1.0 (defensive security testing)"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
EVIL_ORIGIN = "https://evil.example"


def _finding(rule_id, title, severity, description, location, remediation, cwe, owasp="A05"):
    return {
        "tool": "secureflow-scanner",
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": "dast",
        "location": location,
        "description": description,
        "remediation": remediation,
        "cwe": cwe,
        "owasp": owasp,
    }


# --------------------------------------------------------------------------- headers
def check_headers(headers, url):
    """Check response headers. `headers` is any mapping of header name -> value."""
    h = {k.lower(): v for k, v in headers.items()}
    out = []
    csp = h.get("content-security-policy")

    if not csp:
        out.append(_finding(
            "SF-HDR-001", "Missing Content-Security-Policy header", "medium",
            "Without a CSP the browser has no second line of defence against XSS and data injection.",
            url, "Send a restrictive Content-Security-Policy, e.g. default-src 'self'.", "CWE-693"))
    elif re.search(r"'unsafe-(inline|eval)'", csp):
        out.append(_finding(
            "SF-HDR-002", "Weak Content-Security-Policy", "medium",
            "The CSP allows 'unsafe-inline' or 'unsafe-eval', which largely cancels its XSS protection.",
            url, "Remove unsafe-inline/unsafe-eval; use nonces or hashes for inline scripts.", "CWE-693"))

    if "x-frame-options" not in h and not (csp and "frame-ancestors" in csp):
        out.append(_finding(
            "SF-HDR-003", "Missing clickjacking protection", "medium",
            "The page can be embedded in a frame on another site.",
            url, "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.", "CWE-1021"))

    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(_finding(
            "SF-HDR-004", "Missing X-Content-Type-Options: nosniff", "low",
            "Browsers may MIME-sniff responses and execute content as a different type.",
            url, "Send X-Content-Type-Options: nosniff.", "CWE-693"))

    if "referrer-policy" not in h:
        out.append(_finding(
            "SF-HDR-005", "Missing Referrer-Policy header", "low",
            "Full URLs may leak to other sites through the Referer header.",
            url, "Send Referrer-Policy: no-referrer or strict-origin-when-cross-origin.", "CWE-200"))

    if "permissions-policy" not in h:
        out.append(_finding(
            "SF-HDR-006", "Missing Permissions-Policy header", "low",
            "Browser features such as camera and geolocation are not explicitly restricted.",
            url, "Send a Permissions-Policy that disables unused features.", "CWE-693"))

    if urlparse(url).scheme == "https" and "strict-transport-security" not in h:
        out.append(_finding(
            "SF-HDR-007", "Missing Strict-Transport-Security header", "medium",
            "Browsers are not told to use HTTPS only, which allows downgrade attacks.",
            url, "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", "CWE-319"))

    for name in ("server", "x-powered-by"):
        value = h.get(name, "")
        if re.search(r"\d+\.\d+", value):
            out.append(_finding(
                "SF-INFO-001", f"{name.title()} header discloses version", "low",
                f"The {name} header reveals software versions ({value}), which helps attackers pick exploits.",
                url, f"Remove or genericise the {name} header.", "CWE-16"))
    return out


# --------------------------------------------------------------------------- CORS
def check_cors(url, session):
    out, seen = [], set()
    for origin in (EVIL_ORIGIN, "null"):
        try:
            resp = session.get(url, headers={"Origin": origin}, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == "*" and "wildcard" not in seen:
            seen.add("wildcard")
            out.append(_finding(
                "SF-CORS-001", "CORS allows any origin (wildcard)", "medium",
                "Access-Control-Allow-Origin: * lets any website read responses from this API.",
                url, "Allow only a fixed list of trusted origins.", "CWE-942"))
        elif acao and acao == origin and "reflect" not in seen:
            seen.add("reflect")
            label = "null origin" if origin == "null" else "arbitrary Origin"
            out.append(_finding(
                "SF-CORS-002", f"CORS reflects {label}" + (" with credentials" if creds else ""),
                "high" if creds else "medium",
                f"The server echoes the request Origin ({origin}) back as allowed"
                + (" and also allows credentials, so a malicious site can read authenticated data." if creds else "."),
                url, "Validate Origin against an allow-list; never reflect it blindly.", "CWE-942"))
    return out


# --------------------------------------------------------------------------- cookies
def check_cookies(set_cookie_headers, url):
    out = []
    for raw in set_cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
        if "secure" not in attrs:
            out.append(_finding(
                "SF-COOKIE-001", f"Cookie '{name}' missing Secure flag", "medium",
                "The cookie can be sent over plain HTTP and intercepted.",
                url, "Set the Secure attribute.", "CWE-614"))
        if "httponly" not in attrs:
            out.append(_finding(
                "SF-COOKIE-002", f"Cookie '{name}' missing HttpOnly flag", "medium",
                "JavaScript can read the cookie, so an XSS bug can steal it.",
                url, "Set the HttpOnly attribute.", "CWE-1004"))
        if "samesite" not in attrs:
            out.append(_finding(
                "SF-COOKIE-003", f"Cookie '{name}' missing SameSite attribute", "low",
                "Without SameSite the cookie is sent on cross-site requests, which helps CSRF.",
                url, "Set SameSite=Lax or Strict.", "CWE-1275", owasp="A01"))
    return out


def set_cookie_headers(resp):
    raw = getattr(getattr(resp, "raw", None), "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        return raw.getlist("Set-Cookie")
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []


# --------------------------------------------------------------------------- exposed files
EXPOSED_PATHS = [
    ("/.env", "SF-EXPOSE-001", "Environment file exposed",
     lambda r: re.search(r"^[A-Z][A-Z0-9_]+=", r.text, re.M) is not None),
    ("/.git/HEAD", "SF-EXPOSE-002", "Git repository exposed",
     lambda r: r.text.startswith("ref:")),
    ("/console", "SF-EXPOSE-003", "Werkzeug debug console exposed",
     lambda r: "Werkzeug" in r.text),
]


def check_exposed_paths(base_url, session):
    out = []
    for path, rule_id, title, validator in EXPOSED_PATHS:
        target = urljoin(base_url, path)
        try:
            resp = session.get(target, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and validator(resp):
            out.append(_finding(
                rule_id, title, "high",
                f"{path} is served to anyone and can contain credentials or source code.",
                target, "Block this path at the web server and rotate any exposed secrets.",
                "CWE-538", owasp="A05"))
    return out


# --------------------------------------------------------------------------- orchestration
def scan(url):
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    base = session.get(url, timeout=TIMEOUT, allow_redirects=False)
    findings = []
    findings += check_headers(base.headers, url)
    findings += check_cookies(set_cookie_headers(base), url)
    findings += check_cors(url, session)
    findings += check_exposed_paths(url, session)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="SecureFlow web scanner")
    parser.add_argument("--url", required=True, help="Target base URL, e.g. http://localhost:5000")
    parser.add_argument("--output", default="webscan.json", help="Where to write the JSON report")
    parser.add_argument("--allow-remote", action="store_true",
                        help="Allow non-localhost targets. Only use on systems you are authorised to test.")
    args = parser.parse_args(argv)

    host = urlparse(args.url).hostname
    if host not in LOCAL_HOSTS and not args.allow_remote:
        print(f"Refusing to scan {host}: only localhost is allowed without --allow-remote.", file=sys.stderr)
        return 2
    try:
        findings = scan(args.url)
    except requests.RequestException as exc:
        print(f"Could not reach {args.url}: {exc}", file=sys.stderr)
        return 2

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({"scanner": "secureflow-scanner", "target": args.url, "findings": findings}, fh, indent=2)
    print(f"{len(findings)} finding(s) written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
