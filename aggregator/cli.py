"""
Merge scanner output into one report and enforce the security gate.

    python -m aggregator.cli --target fixed --reports reports --out out

Exit codes: 0 gate passed, 1 gate failed, 2 nothing to aggregate.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import outputs
from .engine import DEFAULT_POLICY, apply_suppressions, dedupe, evaluate_gate, summarise
from .parsers import parse_gitleaks, parse_semgrep, parse_trivy, parse_webscan, parse_zap

# (report file name, tool name used by the policy, parser)
SOURCES = [
    ("gitleaks.json", "gitleaks", parse_gitleaks),
    ("semgrep.json", "semgrep", parse_semgrep),
    ("trivy-fs.json", "trivy-fs", lambda d: parse_trivy(d, "fs")),
    ("trivy-image.json", "trivy-image", lambda d: parse_trivy(d, "image")),
    ("zap.json", "zap", parse_zap),
    ("webscan.json", "webscan", parse_webscan),
]


def _load_json(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    return json.loads(text) if text else None


def run(args):
    findings, tools_run, notes = [], [], []
    for filename, tool, parser in SOURCES:
        path = Path(args.reports) / filename
        if not path.exists():
            notes.append(f"No output from {tool} ({filename} not found).")
            continue
        try:
            findings += parser(_load_json(path))
            tools_run.append(tool)
        except (ValueError, KeyError, TypeError) as exc:
            notes.append(f"Could not read {filename}: {exc}")
    if not tools_run:
        print("No scanner output found - nothing to aggregate.", file=sys.stderr)
        return 2

    policy = _load_json(args.policy) if args.policy and Path(args.policy).exists() else DEFAULT_POLICY
    suppressions = _load_json(args.suppressions) if args.suppressions and Path(args.suppressions).exists() else []

    findings = dedupe(findings)
    notes += apply_suppressions(findings, suppressions)
    summary = summarise(findings)
    gate = evaluate_gate(summary, policy, tools_run)
    meta = {
        "target": args.target, "commit": args.commit, "run_url": args.run_url,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "tools_run": tools_run, "tools_missing": [s[1] for s in SOURCES if s[1] not in tools_run],
    }
    report = outputs.build_report(meta, findings, summary, gate, notes)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    outputs.write_json(report, out / "report.json")
    (out / "report.html").write_text(outputs.render_html(report), encoding="utf-8")
    (out / "summary.md").write_text(outputs.to_markdown(report), encoding="utf-8")
    (out / "secureflow.sarif").write_text(
        json.dumps(outputs.to_sarif(findings, args.source_root), indent=2), encoding="utf-8")

    sev = summary["by_severity"]
    print(f"[{args.target}] {summary['total']} findings "
          f"(critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, low {sev['low']}) "
          f"risk {summary['risk_score']}/100 grade {summary['grade']}")
    for note in notes:
        print(f"  note: {note}")
    if gate["passed"]:
        print("SECURITY GATE: PASSED")
        return 0
    print("SECURITY GATE: FAILED")
    for reason in gate["reasons"]:
        print(f"  - {reason}")
    return 1


def main(argv=None):
    p = argparse.ArgumentParser(description="SecureFlow aggregator and security gate")
    p.add_argument("--target", required=True, help="Name of what was scanned, e.g. vulnerable or fixed")
    p.add_argument("--reports", default="reports", help="Directory with raw scanner JSON files")
    p.add_argument("--out", default="out", help="Output directory")
    p.add_argument("--policy", default="policy/secureflow-policy.json")
    p.add_argument("--suppressions", default="policy/suppressions.json")
    p.add_argument("--source-root", default="", help="Folder that was scanned (used to build SARIF file paths)")
    p.add_argument("--commit", default="")
    p.add_argument("--run-url", default="")
    return run(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
