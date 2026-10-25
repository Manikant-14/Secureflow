import json
import re
from datetime import date

from aggregator import cli, outputs, owasp, site
from aggregator.engine import (Finding, apply_suppressions, dedupe, evaluate_gate, summarise)
from aggregator.parsers import parse_gitleaks, parse_semgrep, parse_trivy, parse_webscan, parse_zap

from conftest import FIXTURES


def load(name):
    return json.loads((FIXTURES / name).read_text())


# ---- parsers
def test_semgrep_severity_and_owasp_mapping():
    f = parse_semgrep(load("semgrep.json"))
    assert [x.severity for x in f] == ["high", "medium", "medium"]
    assert f[0].owasp == "A03" and f[0].cwe == "CWE-89"   # 2021 hint wins
    assert f[1].owasp == "A08"                              # 2017 hint ignored, CWE-502 -> A08
    assert f[2].owasp == "A02"                              # CWE-327


def test_gitleaks_never_stores_the_secret():
    f = parse_gitleaks(load("gitleaks.json"))
    assert len(f) == 1 and f[0].severity == "high" and f[0].owasp == "A07"
    assert "x9Fq2LmZ7pRt4VbN8cYd1HsK6wJe3GaU" not in json.dumps(f[0].to_dict())


def test_gitleaks_handles_empty_report():
    assert parse_gitleaks(None) == [] and parse_gitleaks([]) == []


def test_trivy_vulns_and_misconfigs():
    f = parse_trivy(load("trivy-fs.json"))
    by_id = {x.rule_id: x for x in f}
    assert by_id["CVE-2020-14343"].severity == "critical" and by_id["CVE-2020-14343"].owasp == "A06"
    assert by_id["CVE-2020-14343"].remediation == "Upgrade PyYAML to 5.4."
    assert by_id["AVD-DS-0002"].category == "config" and by_id["AVD-DS-0002"].owasp == "A05"


def test_trivy_os_vs_language_packages():
    f = parse_trivy(load("trivy-image.json"), "image")
    cats = {x.rule_id: x.category for x in f}
    assert cats["CVE-2024-0001"] == "container" and cats["CVE-2020-14343"] == "sca"


def test_zap_alerts():
    f = parse_zap(load("zap.json"))
    csp = f[0]
    assert csp.severity == "medium" and csp.count == 3 and csp.owasp == "A05"
    assert "<p>" not in csp.description
    assert f[1].severity == "low" and f[2].severity == "info" and f[2].cwe == ""


def test_webscan_findings():
    f = parse_webscan(load("webscan.json"))
    assert f[0].severity == "high" and f[0].owasp == "A05"


# ---- OWASP mapping
def test_owasp_resolution_order():
    assert owasp.resolve("CWE-89") == "A03"
    assert owasp.resolve("", "A05:2021 - Security Misconfiguration") == "A05"
    assert owasp.resolve("", "A1:2017 - Injection", "sql injection found") == "A03"  # old year ignored, keyword used
    assert owasp.resolve("", "", "totally unrelated words") == "NA"
    assert owasp.normalize_cwe(["CWE-79: XSS"]) == "CWE-79" and owasp.normalize_cwe("-1") == ""


# ---- engine
def test_trivy_duplicates_across_fs_and_image_collapse():
    both = parse_trivy(load("trivy-fs.json")) + parse_trivy(load("trivy-image.json"), "image")
    deduped = dedupe(both)
    assert sum(1 for f in deduped if f.rule_id == "CVE-2020-14343") == 1


def test_scoring_and_grades():
    clean = summarise([])
    assert clean["risk_score"] == 0 and clean["grade"] == "A"
    f = [Finding("t", "r1", "x", "critical"), Finding("t", "r2", "y", "high")]
    s = summarise(f)
    assert s["risk_score"] == 17 and s["grade"] == "C"
    many = [Finding("t", f"r{i}", "x", "critical") for i in range(20)]
    assert summarise(many)["risk_score"] == 100 and summarise(many)["grade"] == "F"


def test_gate_thresholds_and_required_tools():
    s = summarise([Finding("t", "r", "x", "high")])
    assert not evaluate_gate(s, {"max_high": 0}, ["a"])["passed"]
    assert evaluate_gate(s, {"max_high": 1}, ["a"])["passed"]
    gate = evaluate_gate(summarise([]), {"required_tools": ["zap"]}, ["semgrep"])
    assert not gate["passed"] and "zap" in gate["reasons"][0]


def test_suppression_rules():
    findings = [Finding("trivy", "CVE-1", "t", "high", location="pkg@1")]
    notes = apply_suppressions(findings, [{"rule_id": "CVE-1", "reason": "not reachable"}])
    assert findings[0].suppressed and notes == []
    assert summarise(findings)["by_severity"]["high"] == 0 and summarise(findings)["suppressed"] == 1


def test_suppression_needs_reason_and_respects_expiry():
    findings = [Finding("trivy", "CVE-1", "t", "high")]
    notes = apply_suppressions(findings, [{"rule_id": "CVE-1", "reason": " "}])
    assert not findings[0].suppressed and "reason" in notes[0]
    notes = apply_suppressions(findings, [{"rule_id": "CVE-1", "reason": "ok", "expires": "2020-01-01"}],
                               today=date(2026, 1, 1))
    assert not findings[0].suppressed and "expired" in notes[0]


# ---- outputs
def test_sarif_only_contains_file_findings():
    findings = parse_semgrep(load("semgrep.json")) + parse_zap(load("zap.json"))
    sarif = outputs.to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 3 and all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in results)
    assert results[0]["level"] == "error"


def test_html_embeds_data_and_cannot_break_out_of_script():
    evil = Finding("t", "r", "</script><img src=x onerror=alert(1)>", "high")
    report = outputs.build_report({"target": "t", "tools_run": [], "tools_missing": []}, [evil],
                                  summarise([evil]), {"passed": False, "reasons": []}, [])
    page = outputs.render_html(report)
    assert "__REPORT_JSON__" not in page
    assert page.count("</script>") == 2  # the two legitimate closing tags only


def test_dashboard_javascript_is_syntactically_valid(tmp_path):
    import shutil, subprocess
    if not shutil.which("node"):
        return
    page = (cli.Path(outputs.TEMPLATE)).read_text()
    scripts = re.findall(r"<script>(.*?)</script>", page, re.S)
    js = tmp_path / "dash.js"
    js.write_text(scripts[0])
    assert subprocess.run(["node", "--check", str(js)]).returncode == 0


# ---- CLI end to end
def run_cli(tmp_path, reports, policy=None):
    out = tmp_path / "out"
    argv = ["--target", "demo", "--reports", str(reports), "--out", str(out),
            "--policy", str(policy or ""), "--suppressions", ""]
    return cli.main(argv), out


def test_cli_fails_the_gate_and_writes_all_outputs(tmp_path):
    code, out = run_cli(tmp_path, FIXTURES)
    assert code == 1
    for name in ("report.json", "report.html", "summary.md", "secureflow.sarif"):
        assert (out / name).exists()
    report = json.loads((out / "report.json").read_text())
    assert report["summary"]["by_severity"]["critical"] >= 1
    assert report["meta"]["tools_missing"] == []


def test_cli_passes_with_lenient_policy(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"max_critical": 99, "max_high": 99}))
    code, _ = run_cli(tmp_path, FIXTURES, policy)
    assert code == 0


def test_cli_fails_closed_when_a_required_scanner_is_missing(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "gitleaks.json").write_text("[]")
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"required_tools": ["gitleaks", "zap"]}))
    code, _ = run_cli(tmp_path, reports, policy)
    assert code == 1


def test_cli_returns_2_when_nothing_found(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    code, _ = run_cli(tmp_path, empty)
    assert code == 2


def test_site_builder(tmp_path):
    for target in ("vulnerable", "fixed"):
        d = tmp_path / "artifacts" / f"secureflow-{target}" / "out"
        d.mkdir(parents=True)
        findings = [Finding("t", "r", "x", "high")] if target == "vulnerable" else []
        report = outputs.build_report({"target": target, "tools_run": [], "tools_missing": []}, findings,
                                      summarise(findings), {"passed": not findings, "reasons": []}, [])
        outputs.write_json(report, d / "report.json")
        (d / "report.html").write_text("<html></html>")
    assert site.build(tmp_path / "artifacts", tmp_path / "site") == 2
    index = (tmp_path / "site" / "index.html").read_text()
    assert "dropped from 1" in index and "to 0" in index
    assert (tmp_path / "site" / "fixed" / "index.html").exists()
