# 🛡️ SecureFlow
### Automated DevSecOps Security Pipeline — IBM Cybersecurity Bootcamp Project
**Built by Manikant | B.Tech CSE, Sharda University**

---

## 📌 Overview

An automated **DevSecOps pipeline** that checks a web application for security flaws on every push, merges the results from six different checks into one report mapped to the **OWASP Top 10**, and **fails the build** when critical or high-severity issues remain.

The repo ships two versions of the same Flask app: one **deliberately vulnerable**, one **hardened**. The pipeline blocks the first and passes the second, and a live dashboard shows the before/after difference.

> ⚠️ `app/vulnerable` is dangerous on purpose. Never expose it to a network. The API key inside it is fake.

---

## 🏗️ Architecture

```
Developer (git push / pull request)
        ↓
   GitHub Actions
        ↓
   ┌────────────────────────────────────┐
   │  Unit tests (pytest)               │  ← proves flaws exist / are fixed
   └────────┬───────────────────────────┘
            ↓
   ┌────────────────────────────────────────────────────────┐
   │  Security scan (runs on BOTH targets in parallel)      │
   │                                                        │
   │  Gitleaks      → hard-coded secrets                    │
   │  Semgrep       → SAST (injection, XSS, unsafe YAML)    │
   │  Trivy fs      → vulnerable dependencies + Dockerfile  │
   │  Trivy image   → vulnerable OS packages in the image   │
   │  OWASP ZAP     → DAST on the running app               │
   │  SecureFlow    → headers, CORS, cookies, exposed files │
   │  scanner (own)                                         │
   └────────┬───────────────────────────────────────────────┘
            ↓
   Aggregator (Python)
   normalise → dedupe → map to OWASP → apply suppressions → score
            ↓
       Security gate
      ┌─────┴─────┐
    PASS         FAIL
      │            │
      │            └─→ build fails, report is still published
      ↓
   Dashboard on GitHub Pages  +  SARIF to GitHub Security tab
```

**Two targets, one pipeline:**
- `vulnerable` → expected to FAIL the gate (that is the demo)
- `fixed` → expected to PASS the gate

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| CI/CD | GitHub Actions |
| Target app | Flask (Python), gunicorn |
| Containers | Docker |
| Secret scanning | Gitleaks |
| SAST | Semgrep |
| SCA, Dockerfile, image scanning | Trivy |
| DAST | OWASP ZAP (baseline scan) |
| Custom scanner | Python + `requests` |
| Aggregator and dashboard | Plain Python (no dependencies), HTML/CSS/JS |
| Reporting | JSON, SARIF, Markdown summary, GitHub Pages |
| Testing | pytest |
| Hosting | GitHub Pages (free) |

---

## 📁 Project Structure

```
secureflow/
├── app/
│   ├── vulnerable/            # Intentionally vulnerable Flask app + Dockerfile
│   └── fixed/                 # The same app, hardened
├── scanner/
│   └── webscan.py             # Custom scanner: headers, CORS, cookies, exposed files
├── aggregator/
│   ├── parsers.py             # Reads each tool's JSON into a common format
│   ├── owasp.py               # CWE / keyword → OWASP Top 10 (2021) mapping
│   ├── engine.py              # Dedupe, suppressions, scoring, security gate
│   ├── outputs.py             # JSON, SARIF, Markdown summary, HTML dashboard
│   ├── cli.py                 # Entry point used by the pipeline
│   ├── site.py                # Builds the GitHub Pages comparison site
│   └── templates/report.html  # Dashboard
├── policy/
│   ├── secureflow-policy.json # Gate thresholds
│   └── suppressions.json      # Documented, expiring exceptions
├── tests/                     # 40 pytest tests
├── .github/workflows/
│   └── secureflow.yml         # The pipeline
└── docs/
    └── PROJECT_REPORT.md      # Report template for submission
```

---

## 🚀 How to Run

### Option A: Run on GitHub (full pipeline)

**1. Create a public repo** named `secureflow` and push the code to `main`
```bash
git init && git add . && git commit -m "SecureFlow: DevSecOps pipeline"
git branch -M main
git remote add origin https://github.com/Manikant-14/secureflow.git
git push -u origin main
```

**2. Enable Pages**
```
Settings → Pages → Source: GitHub Actions
```

**3. Open the Actions tab** — the `SecureFlow` workflow starts on its own
```
✅ unit-tests            passed
🔴 security-scan (vulnerable)   gate failed   ← expected
✅ security-scan (fixed)        gate passed
✅ publish               dashboard deployed
```

**4. Open the dashboard**
```
https://manikant-14.github.io/Secureflow/
```

The overall workflow run stays green on purpose, so the report always publishes.

### Option B: Run locally (VS Code)

Requirements: Python 3.10+ and Git. Docker is optional.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -q                          # 40 tests
```

Try the custom scanner without Docker (use two terminals with the venv active):
```bash
# Terminal 1
cd app/vulnerable
pip install Flask pyyaml
python app.py

# Terminal 2 (project root)
python -m scanner.webscan --url http://localhost:5000 --output webscan.json
```

Or run the vulnerable app in a container, bound to localhost only:
```bash
docker build -t Secureflow-vulnerable app/vulnerable
docker run --rm -p 127.0.0.1:5000:5000 Secureflow-vulnerable
```

---

## 🔍 Pipeline Capabilities

### What each check catches

| Check | Tool | Catches |
|---|---|---|
| Secrets | Gitleaks | Hard-coded keys and tokens |
| SAST | Semgrep | SQL injection, XSS, command injection, unsafe YAML, weak hashing |
| Dependencies | Trivy | Known CVEs in `requirements.txt` |
| Dockerfile | Trivy | Running as root, missing HEALTHCHECK |
| Image | Trivy | Vulnerable OS packages in the base image |
| DAST | OWASP ZAP baseline | Passive web issues on the running app |
| Web scanner | `scanner/webscan.py` | Missing security headers, weak CORS, insecure cookies, version disclosure, exposed `.env` / `.git` |

### Custom web scanner
Written from scratch in Python. It sends a handful of normal GET requests and reports:

| Rule group | Examples |
|---|---|
| Security headers | CSP, clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy, HSTS (HTTPS only) |
| CORS | Wildcard origin, reflected origin, reflected origin with credentials (high) |
| Cookies | Missing `Secure`, `HttpOnly`, `SameSite` |
| Exposed files | `/.env`, `/.git/HEAD`, Werkzeug debug console |
| Information leaks | `Server` / `X-Powered-By` version numbers |

By default it **refuses any target that is not localhost**.

### Aggregator
Every tool reports in a different format. The aggregator:
1. Converts each report into one common finding format
2. Removes duplicates (the same CVE found by Trivy fs and Trivy image counts once)
3. Maps each finding to an **OWASP Top 10 (2021)** category
4. Applies documented suppressions
5. Calculates a **risk score (0-100)** and a grade (A to F)
6. Evaluates the **security gate**

The aggregator **fails closed**: if a required scanner produces no output, the gate fails instead of silently passing. Secrets found by Gitleaks are never copied into the report.

### Security gate
Configured in `policy/secureflow-policy.json`:
```json
{
  "max_critical": 0,
  "max_high": 0,
  "max_medium": null,
  "required_tools": ["gitleaks", "semgrep", "trivy-fs", "trivy-image", "zap", "webscan"]
}
```
Set `max_medium` to a number to gate on medium findings as well.

### Suppressions
Known findings can be accepted, but only with a written reason and an expiry date. A suppression without a reason is ignored, and an expired one stops applying:
```json
[{
  "rule_id": "CVE-2024-0001",
  "location_contains": "libssl3",
  "reason": "Not reachable: the app does not use TLS",
  "expires": "2027-01-31"
}]
```

---

## 🐛 Vulnerabilities Demonstrated

The vulnerable app contains these flaws on purpose. The fixed app resolves every one.

| Flaw | Where | OWASP 2021 | Detected by | Fix in `app/fixed` |
|---|---|---|---|---|
| SQL injection | `/search`, `/login` | A03 Injection | Semgrep | Parameterised queries |
| Reflected XSS | `/search` | A03 Injection | Semgrep | Template auto-escaping |
| OS command injection | `/ping` | A03 Injection | Semgrep | Endpoint removed |
| Unsafe YAML load | `/config` | A08 Integrity | Semgrep | `yaml.safe_load` |
| MD5 password hashing | login | A02 Crypto | Semgrep | `generate_password_hash` |
| Hard-coded API key | `app.py` | A07 Auth | Gitleaks | Environment variables |
| Outdated dependencies | `requirements.txt` | A06 Components | Trivy | Upgraded pins |
| Container runs as root | `Dockerfile` | A05 Misconfig | Trivy | `USER appuser` |
| Missing headers, weak cookies | all responses | A05 Misconfig | ZAP, custom scanner | Security headers, cookie flags |
| CORS reflects any origin | all responses | A05 Misconfig | Custom scanner | Origin allow-list |
| Exposed `.env` | `/.env` | A05 Misconfig | Custom scanner | Route removed |
| Broken object-level authorisation (BOLA) | `/api/users/<id>` | A01 Access Control | pytest | Ownership check |

> BOLA cannot be detected by generic scanners, so it is covered by tests rather than by the pipeline.

---

## 📊 Results

| | Vulnerable app | Hardened app |
|---|---|---|
| Critical + high findings | _fill in after first run_ | _fill in after first run_ |
| Risk score (0-100) | _fill in_ | _fill in_ |
| Security gate | ❌ Fails | ✅ Passes |

_Add a screenshot of the dashboard here._

---

## 📸 Dashboard Features

- Plain-language verdict at the top ("The security gate failed: N critical or high findings")
- Severity strip showing the proportion of critical, high, medium, low and info findings
- OWASP Top 10 breakdown with counts per category
- Scanner list showing which tools ran and which produced no output
- Searchable findings list, filterable by severity, tool and OWASP category
- Expandable details for each finding: description, fix, tool, rule, CWE
- Suppressed findings shown with their written reason
- Light and dark mode, keyboard accessible, works on mobile
- Comparison page showing the vulnerable and hardened apps side by side

---

## 🔌 Vulnerable App Endpoints

| Method | Endpoint | Purpose | Flaw |
|---|---|---|---|
| GET | `/` | Home page, sets a session cookie | Insecure cookie |
| GET | `/health` | Health check | — |
| GET | `/search?q=` | Product search | SQL injection, reflected XSS |
| POST | `/login` | Login | SQL injection, MD5 |
| GET | `/ping?host=` | Network check | Command injection |
| POST | `/config` | Load YAML config | Unsafe deserialisation |
| GET | `/api/users/<id>` | User profile | BOLA |
| GET | `/.env` | — | Exposed secrets |

---

## 🧪 Testing

```bash
pytest -q        # 40 tests
```

| Test group | What it proves |
|---|---|
| App tests | Each exploit works on the vulnerable app and is blocked on the fixed app |
| Scanner tests | Header, CORS and cookie rules fire correctly; localhost-only guard works |
| Parser tests | Each tool's output is read correctly; secrets are never stored |
| Engine tests | OWASP mapping, dedupe, scoring, gate thresholds, suppression rules |
| Output tests | SARIF structure, dashboard cannot be broken by hostile scanner text |
| End-to-end | The CLI writes all outputs, fails the gate, and fails closed if a scanner is missing |

---

## ⚙️ Design Decisions

**Why scan two versions of the same app?**
A pass/fail result on its own is hard to judge. Showing a vulnerable app fail and a fixed app pass proves the pipeline detects real problems and does not just report green.

**Why a custom scanner next to existing tools?**
Writing the scanner shows how header, CORS and cookie checks actually work, and it covers web-layer issues that code scanners cannot see.

**Why an aggregator instead of reading six reports?**
Each tool uses its own format and severity scale. One normalised report with one OWASP mapping and one gate rule is what a team can act on.

**Why does the gate fail closed?**
If ZAP crashes and produces nothing, a naive pipeline would report "0 findings, passed". Treating a missing scanner as a failure prevents a false sense of security.

**Why require a reason and expiry for suppressions?**
Silent ignore-lists hide real risk over time. Forcing a written reason and an end date keeps exceptions visible and temporary.

**Why plain Python and a static dashboard?**
No server, no database and no dependencies mean the dashboard is free to host on GitHub Pages and easy for anyone to audit.

**Why GitHub Actions and not Colab?**
The pipeline needs Docker, scanners and a CI trigger on every push. That is what GitHub Actions provides, for free.

---

## 🔧 Troubleshooting

| Problem | Fix |
|---|---|
| The `fixed` target fails on a dependency or base-image CVE | New CVEs appear over time. Bump the pinned version in `app/fixed/requirements.txt` or the Docker base image tag, or add a documented suppression. The pipeline is working as intended. |
| Pages deploy fails | Check Settings → Pages → Source is set to **GitHub Actions** |
| SARIF upload fails | It needs a public repo or GitHub Advanced Security. The step is optional. |
| Dependabot and code-scanning alerts on `app/vulnerable` | Expected. They are part of the demo. |
| A required scanner is "missing" | Open that step's log in the Actions run. The gate fails on purpose until it works. |

---

## ⚖️ Ethics

Only scan systems you own or have written permission to test. The custom scanner refuses non-localhost targets unless you pass `--allow-remote`. The vulnerable app must only ever run on your own machine or a CI runner.

---

## 🔮 Future Improvements

- Pull request comments with a findings summary
- Trend chart of findings per run
- SBOM generation with Syft or Trivy
- Pre-commit hook running Gitleaks
- ZAP full scan with authentication for active SQLi and XSS tests
- LLM-assisted triage that explains findings and proposes fixes

---

## 👤 Author

**Manikant**
- GitHub: [github.com/Manikant-14](https://github.com/Manikant-14)
- LinkedIn: [linkedin.com/in/manikant14](https://linkedin.com/in/manikant14)
- Email: manikantmgr14@gmail.com

---

*Built for the IBM Cybersecurity Bootcamp project submission — October 2026*
