"""Core data model, de-duplication, suppression, scoring and the security gate."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import date

SEVERITIES = ("critical", "high", "medium", "low", "info")
WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
GRADES = [(0, "A"), (10, "B"), (25, "C"), (50, "D")]  # risk score <= limit -> grade, else F


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: str
    category: str = ""          # sast | secrets | sca | container | config | dast
    location: str = ""          # human-readable place: file, URL or package
    file: str = ""              # repo-relative file path, when there is one (used for SARIF)
    line: int | None = None
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""             # OWASP Top 10 code, e.g. A03
    count: int = 1
    suppressed: bool = False
    suppression_reason: str = ""

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})


def severity_rank(sev):
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def dedupe(findings):
    """Drop exact duplicates (same tool, rule, place). Keeps the more severe copy."""
    best = {}
    for f in findings:
        key = (f.tool, f.rule_id, f.location, f.line)
        if key not in best or severity_rank(f.severity) < severity_rank(best[key].severity):
            best[key] = f
    return sorted(best.values(), key=lambda f: (severity_rank(f.severity), f.tool, f.location, f.line or 0))


def apply_suppressions(findings, suppressions, today=None):
    """Mark findings as suppressed. Returns notes about suppressions that were ignored."""
    today = today or date.today()
    notes, active = [], []
    for s in suppressions or []:
        rule = s.get("rule_id", "")
        if not rule or not str(s.get("reason", "")).strip():
            notes.append(f"Ignored a suppression for '{rule}': rule_id and a written reason are required.")
            continue
        expires = s.get("expires")
        if expires:
            try:
                if date.fromisoformat(expires) < today:
                    notes.append(f"Suppression for '{rule}' expired on {expires} and no longer applies.")
                    continue
            except ValueError:
                notes.append(f"Ignored a suppression for '{rule}': invalid expiry date '{expires}'.")
                continue
        active.append(s)
    for f in findings:
        for s in active:
            if s["rule_id"] == f.rule_id and s.get("location_contains", "") in f.location:
                f.suppressed = True
                f.suppression_reason = s["reason"]
                break
    return notes


def summarise(findings):
    live = [f for f in findings if not f.suppressed]
    by_severity = {s: 0 for s in SEVERITIES}
    by_tool, by_owasp = {}, {}
    for f in live:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
        by_owasp[f.owasp or "NA"] = by_owasp.get(f.owasp or "NA", 0) + 1
    score = min(100, sum(WEIGHTS.get(f.severity, 0) for f in live))
    grade = next((g for limit, g in GRADES if score <= limit), "F")
    return {
        "total": len(live),
        "suppressed": len(findings) - len(live),
        "by_severity": by_severity,
        "by_tool": by_tool,
        "by_owasp": by_owasp,
        "risk_score": score,
        "grade": grade,
    }


DEFAULT_POLICY = {"max_critical": 0, "max_high": 0, "max_medium": None, "max_low": None, "required_tools": []}


def evaluate_gate(summary, policy, tools_run):
    policy = {**DEFAULT_POLICY, **(policy or {})}
    reasons = []
    for sev in ("critical", "high", "medium", "low"):
        limit = policy.get(f"max_{sev}")
        if limit is not None and summary["by_severity"].get(sev, 0) > limit:
            reasons.append(f"{summary['by_severity'][sev]} {sev} finding(s) exceed the allowed maximum of {limit}.")
    missing = [t for t in policy.get("required_tools", []) if t not in tools_run]
    for tool in missing:
        reasons.append(f"Required scanner output is missing: {tool}. The gate fails closed.")
    return {"passed": not reasons, "reasons": reasons, "policy": policy}
