# SecureFlow: Project Report

**Name:** <your name>  **Programme:** IBM Cybersecurity Bootcamp  **Date:** <date>  
**Repository:** https://github.com/<you>/secureflow  **Dashboard:** https://<you>.github.io/secureflow/

## 1. Problem
Security checks that run only at the end of development find problems late, when they are
expensive to fix. Teams need automated checks on every commit that can block risky changes.

## 2. Objective
Build a CI/CD pipeline that automatically scans a web application, consolidates the results,
and blocks the build when serious vulnerabilities are present.

## 3. Approach
Describe the architecture diagram from the README in your own words.
Explain each stage: secrets, SAST, SCA, container, DAST, custom scanner, aggregation, gate.

## 4. Implementation
- Target applications: vulnerable and hardened Flask apps (list the flaws and the fixes)
- Pipeline: GitHub Actions stages and tools
- Custom code: web scanner, aggregator, OWASP mapping, scoring, gate, suppressions
- Dashboard and GitHub Pages deployment

## 5. Vulnerabilities demonstrated and fixes
| Flaw | OWASP 2021 | Detected by | Fix |
|---|---|---|---|
| SQL injection in /search and /login | A03 | Semgrep | Parameterised queries |
| Reflected XSS in /search | A03 | Semgrep | Template auto-escaping |
| OS command injection in /ping | A03 | Semgrep | Endpoint removed |
| Unsafe YAML load | A08 | Semgrep | `yaml.safe_load` |
| MD5 password hashing | A02 | Semgrep | `generate_password_hash` |
| Hard-coded API key | A07 | Gitleaks | Environment variables |
| Outdated dependencies | A06 | Trivy | Upgraded pins |
| Container runs as root | A05 | Trivy | `USER appuser` |
| Missing headers, weak cookies | A05 | ZAP, custom scanner | Security headers, cookie flags |
| CORS reflects any origin | A05 | Custom scanner | Origin allow-list |
| Exposed `.env` | A05 | Custom scanner | Route removed |
| BOLA on /api/users/<id> | A01 | pytest | Ownership check |

## 6. Results
Insert the results table and dashboard screenshots (vulnerable vs fixed).

## 7. Testing
Describe the pytest suite: exploit tests on the vulnerable app, regression tests on the fixed
app, parser and gate tests. State the number of tests.

## 8. Limitations
- ZAP baseline is passive; it does not actively exploit.
- BOLA is not detectable by generic scanners; it is covered by tests, not by the pipeline.
- Pinned dependency versions need regular updates.

## 9. Future work
PR comments, trend tracking, SBOM, LLM-assisted triage.

## 10. Learnings
What you learned about DevSecOps, tool trade-offs, false positives and gate design.
