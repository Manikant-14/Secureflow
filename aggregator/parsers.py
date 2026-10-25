"""Turn each scanner's raw JSON into common Finding objects."""
from __future__ import annotations

import re

from .engine import Finding
from .owasp import normalize_cwe, resolve

TRIVY_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _strip_html(text):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()


def _humanize(rule_id):
    last = rule_id.split(".")[-1].replace("-", " ").replace("_", " ").strip()
    return last[:1].upper() + last[1:] if last else rule_id


def _first(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else ""
    return value or ""


def parse_semgrep(data):
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        rule = r.get("check_id", "semgrep")
        message = extra.get("message", "")
        cwe = normalize_cwe(meta.get("cwe"))
        out.append(Finding(
            tool="semgrep", rule_id=rule, title=_humanize(rule),
            severity=SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "medium"),
            category="sast", location=r.get("path", ""), file=r.get("path", ""),
            line=(r.get("start") or {}).get("line"),
            description=message, remediation=extra.get("fix", "") or "",
            cwe=cwe, owasp=resolve(cwe, _first(meta.get("owasp")), f"{rule} {message}"),
        ))
    return out


def parse_gitleaks(data):
    out = []
    for leak in data or []:
        rule = leak.get("RuleID", "secret")
        out.append(Finding(
            tool="gitleaks", rule_id=rule,
            title=f"Hard-coded secret ({leak.get('Description') or rule})",
            severity="high", category="secrets",
            location=leak.get("File", ""), file=leak.get("File", ""), line=leak.get("StartLine"),
            description="A credential-like value is committed in source code. The value is not stored in this report.",
            remediation="Remove it from source, rotate it, and load it from an environment variable or secret manager.",
            cwe="CWE-798", owasp="A07",
        ))
    return out


def parse_trivy(data, source="fs"):
    """`source` is 'fs' or 'image'; it only names the scan, the Class field decides the category."""
    out = []
    tool = "trivy"
    for res in (data or {}).get("Results") or []:
        target = res.get("Target", "")
        os_pkgs = res.get("Class") == "os-pkgs"
        for v in res.get("Vulnerabilities") or []:
            pkg, ver, fixed = v.get("PkgName", ""), v.get("InstalledVersion", ""), v.get("FixedVersion")
            vid = v.get("VulnerabilityID", "")
            out.append(Finding(
                tool=tool, rule_id=vid, title=f"{vid} in {pkg} {ver}",
                severity=TRIVY_SEVERITY.get(str(v.get("Severity", "")).upper(), "info"),
                category="container" if os_pkgs else "sca",
                location=f"{pkg}@{ver}", file="" if os_pkgs else target,
                description=(v.get("Title") or v.get("Description") or "")[:400],
                remediation=f"Upgrade {pkg} to {fixed}." if fixed else "No fixed version available yet.",
                cwe=normalize_cwe((v.get("CweIDs") or [""])[0]), owasp="A06",
            ))
        for m in res.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() == "PASS":
                continue
            out.append(Finding(
                tool=tool, rule_id=m.get("AVDID") or m.get("ID", "misconfig"),
                title=m.get("Title", "Misconfiguration"),
                severity=TRIVY_SEVERITY.get(str(m.get("Severity", "")).upper(), "info"),
                category="config", location=target, file=target,
                line=(m.get("CauseMetadata") or {}).get("StartLine") or None,
                description=m.get("Message", ""), remediation=m.get("Resolution", ""),
                owasp="A05",
            ))
    return out


def parse_zap(data):
    out = []
    for site in (data or {}).get("site", []):
        for a in site.get("alerts", []):
            instances = a.get("instances") or []
            uri = instances[0].get("uri", "") if instances else site.get("@name", "")
            cwe = normalize_cwe(a.get("cweid"))
            name = a.get("name") or a.get("alert", "ZAP alert")
            out.append(Finding(
                tool="zap", rule_id=f"ZAP-{a.get('pluginid') or a.get('alertRef', '')}", title=name,
                severity=ZAP_RISK.get(str(a.get("riskcode", "0")), "info"), category="dast",
                location=uri, description=_strip_html(a.get("desc")),
                remediation=_strip_html(a.get("solution")), cwe=cwe,
                owasp=resolve(cwe, "", name), count=int(a.get("count") or len(instances) or 1),
            ))
    return out


def parse_webscan(data):
    out = []
    for item in (data or {}).get("findings", []):
        f = Finding.from_dict(item)
        f.owasp = resolve(f.cwe, f.owasp, f.title)
        out.append(f)
    return out
