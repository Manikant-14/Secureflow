"""Build the GitHub Pages site: one comparison page plus each target's full report."""
from __future__ import annotations

import argparse
import html
import json
import shutil
from pathlib import Path

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureFlow results</title>
<style>
:root{{--bg:#f6f7f9;--ink:#16202b;--muted:#5b6876;--card:#fff;--line:#dde2e8;--bad:#b4234a;--good:#1f7a5c}}
@media (prefers-color-scheme:dark){{:root{{--bg:#11161c;--ink:#e6ebf1;--muted:#9aa7b5;--card:#19202a;--line:#2a3441;--bad:#ff6b8b;--good:#4cc9a0}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 "IBM Plex Sans",system-ui,sans-serif}}
main{{max-width:980px;margin:0 auto;padding:40px 20px}}
h1{{font-size:2rem;margin:0 0 6px}} p.lead{{color:var(--muted);margin:0 0 28px;max-width:62ch}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px}}
.card h2{{margin:0 0 4px;font-size:1.25rem}} .verdict{{font-weight:600}}
.pass{{color:var(--good)}} .fail{{color:var(--bad)}}
table{{border-collapse:collapse;width:100%;margin:12px 0}} td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}}
a{{color:inherit}}
</style></head><body><main>
<h1>SecureFlow results</h1>
<p class="lead">{lead}</p>
<div class="grid">{cards}</div>
</main></body></html>"""

CARD = """<section class="card"><h2>{target}</h2>
<p class="verdict {cls}">Gate {verdict}. Risk {score}/100, grade {grade}.</p>
<table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
<tr><td>{c}</td><td>{h}</td><td>{m}</td><td>{l}</td></tr></table>
<p><a href="{target}/index.html">Open full report</a> | <a href="{target}/report.json">JSON</a></p></section>"""


def build(input_dir, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reports = []
    for report_json in sorted(Path(input_dir).glob("**/report.json")):
        data = json.loads(report_json.read_text(encoding="utf-8"))
        target = data["meta"]["target"]
        dest = out / target
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy(report_json, dest / "report.json")
        report_html = report_json.with_name("report.html")
        if report_html.exists():
            shutil.copy(report_html, dest / "index.html")
        reports.append(data)
    # vulnerable first, so the page reads "before -> after"
    reports.sort(key=lambda d: (d["meta"]["target"] != "vulnerable", d["meta"]["target"]))

    cards = []
    for d in reports:
        s, g = d["summary"], d["gate"]
        sev = s["by_severity"]
        cards.append(CARD.format(
            target=html.escape(d["meta"]["target"]), cls="pass" if g["passed"] else "fail",
            verdict="passed" if g["passed"] else "failed", score=s["risk_score"], grade=html.escape(s["grade"]),
            c=sev["critical"], h=sev["high"], m=sev["medium"], l=sev["low"]))

    by = {d["meta"]["target"]: d["summary"]["by_severity"] for d in reports}
    lead = "Automated security checks on every push."
    if "vulnerable" in by and "fixed" in by:
        bad = by["vulnerable"]["critical"] + by["vulnerable"]["high"]
        good = by["fixed"]["critical"] + by["fixed"]["high"]
        lead = (f"Critical and high findings dropped from {bad} in the vulnerable app "
                f"to {good} in the hardened app. The pipeline blocks the first and passes the second.")
    (out / "index.html").write_text(PAGE.format(lead=html.escape(lead), cards="".join(cards)), encoding="utf-8")
    return len(reports)


def main(argv=None):
    p = argparse.ArgumentParser(description="Build the SecureFlow GitHub Pages site")
    p.add_argument("--input", default="artifacts")
    p.add_argument("--out", default="site")
    args = p.parse_args(argv)
    count = build(args.input, args.out)
    print(f"Built site with {count} report(s) in {args.out}")
    return 0 if count else 1


if __name__ == "__main__":
    raise SystemExit(main())
