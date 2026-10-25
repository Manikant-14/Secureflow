"""Write the JSON report, SARIF, Markdown summary and HTML dashboard."""
from __future__ import annotations

import json
from pathlib import Path

from .engine import SEVERITIES
from .owasp import OWASP_2021, label

TEMPLATE = Path(__file__).parent / "templates" / "report.html"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def build_report(meta, findings, summary, gate, notes):
    return {
        "meta": meta,
        "summary": summary,
        "gate": gate,
        "notes": notes,
        "owasp_names": OWASP_2021,
        "findings": [f.to_dict() for f in findings],
    }


def write_json(report, path):
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")


def render_html(report):
    # "</" is escaped so scanner text can never close the <script> tag early.
    data = json.dumps(report).replace("</", "<\\/")
    return TEMPLATE.read_text(encoding="utf-8").replace("__REPORT_JSON__", data)


def to_sarif(findings, source_root=""):
    """Only findings that point at a file are exported; GitHub needs a location for each alert."""
    rules, results = {}, []
    for f in findings:
        if f.suppressed or not f.file:
            continue
        path = Path(f.file)
        if source_root and not path.exists() and (Path(source_root) / path).exists():
            path = Path(source_root) / path
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.title[:120],
            "shortDescription": {"text": f.title[:120]},
            "fullDescription": {"text": (f.description or f.title)[:500]},
            "help": {"text": f.remediation or "See tool documentation."},
            "properties": {
                "security-severity": SECURITY_SEVERITY.get(f.severity, "1.0"),
                "tags": ["security", f.tool] + ([label(f.owasp)] if f.owasp in OWASP_2021 else []),
            },
        })
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}. {f.description}".strip()[:900]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path.as_posix()},
                "region": {"startLine": f.line or 1},
            }}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SecureFlow", "rules": list(rules.values())}}, "results": results}],
    }


def to_markdown(report):
    m, s, g = report["meta"], report["summary"], report["gate"]
    lines = [
        f"## SecureFlow: `{m.get('target', '?')}`",
        "",
        f"**Gate: {'PASSED' if g['passed'] else 'FAILED'}** | risk score {s['risk_score']}/100 (grade {s['grade']}) "
        f"| {s['total']} finding(s), {s['suppressed']} suppressed",
        "",
    ]
    lines += [f"- {r}" for r in g["reasons"]]
    lines += ["", "| Critical | High | Medium | Low | Info |", "|---|---|---|---|---|"]
    lines.append("| " + " | ".join(str(s["by_severity"].get(sev, 0)) for sev in SEVERITIES) + " |")
    top = [f for f in report["findings"] if not f["suppressed"]][:10]
    if top:
        lines += ["", "Top findings:", ""]
        lines += [f"- **{f['severity']}** ({f['tool']}) {f['title']} - `{f['location']}`" for f in top]
    lines += [f"- Note: {n}" for n in report.get("notes", [])]
    return "\n".join(lines) + "\n"
