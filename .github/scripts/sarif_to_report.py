#!/usr/bin/env python3
"""
Turn a CodeQL SARIF file into a single-page, non-technical HTML report
grouped by vulnerability category.

Usage:
    python sarif_to_report.py <sarif-file-or-dir> <output.html>
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path


# ---------- helpers ----------------------------------------------------------

def severity_bucket(score: float, level: str) -> str:
    """Map CodeQL's numeric security-severity (or SARIF level) to a label."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    # Fall back to SARIF level if no numeric score
    return {"error": "High", "warning": "Medium", "note": "Low"}.get(level, "Info")


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLOR = {
    "Critical": "#b91c1c",
    "High":     "#ea580c",
    "Medium":   "#ca8a04",
    "Low":      "#0369a1",
    "Info":     "#475569",
}
# Plain-English descriptions for common CWE / CodeQL rule families
CATEGORY_DESCRIPTIONS = {
    "sql-injection":     "User input flows directly into a database query. Attackers can read, modify, or destroy data.",
    "command-injection": "User input flows into a shell command. Attackers can run arbitrary commands on the server.",
    "path-injection":    "User input controls a file path. Attackers can read or write files outside intended folders.",
    "path-combine":      "File-path building has a flaw where one segment can silently override another.",
    "xss":               "User input is rendered in HTML without escaping. Attackers can run scripts in users' browsers.",
    "log-forging":       "Untrusted input is written to logs as-is. Attackers can fake log entries to confuse audits.",
    "unsafe-deserialization": "Untrusted data is turned back into objects. Attackers can run arbitrary code.",
    "url-redirection":   "User input controls a redirect target. Attackers can send users to malicious sites.",
    "ssrf":              "Server makes a network request to a URL the user controls. Attackers can reach internal systems.",
    "xxe":               "XML parser allows external entities. Attackers can read local files or hit internal URLs.",
    "xml":               "XML processing accepts untrusted input that may load external resources or DTDs.",
    "ecb-encryption":    "Encryption uses ECB mode, which leaks patterns in the data.",
    "weak-cryptographic-algorithm": "A weak or broken algorithm (e.g. MD5, SHA-1, DES) is used for security.",
    "hard-coded-credentials": "Passwords or keys are written directly in source code.",
    "insecure-randomness": "Randomness comes from a predictable source. Tokens or keys can be guessed.",
    "catch-of-all-exceptions": "Code swallows every error, hiding real problems from monitoring.",
    "missing-validation": "Input from outside the system is used without being checked first.",
    "insecure-dtd-handling": "XML processing allows Document Type Definitions, which can fetch external data.",
}


def human_category(rule_id: str) -> str:
    """Make 'cs/sql-injection' → 'SQL injection' for the headings."""
    short = rule_id.split("/")[-1]
    return short.replace("-", " ").replace("_", " ").capitalize()


def category_key(rule_id: str) -> str:
    return rule_id.split("/")[-1]


# ---------- main -------------------------------------------------------------

def collect_sarif_files(arg: str) -> list[Path]:
    p = Path(arg)
    if p.is_dir():
        return sorted(p.rglob("*.sarif"))
    if p.is_file():
        return [p]
    return []


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    src, out_path = sys.argv[1], Path(sys.argv[2])
    files = collect_sarif_files(src)
    if not files:
        print(f"No SARIF files found at {src}", file=sys.stderr)
        # Still write an empty-state report so artifact upload has something
        out_path.write_text(render([], 0, files=[]), encoding="utf-8")
        return 0

    # Build a rule-id → metadata map and bucket findings by rule.
    rule_meta: dict[str, dict] = {}
    findings_by_rule: dict[str, list[dict]] = defaultdict(list)
    total = 0

    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Skipping {f}: {e}", file=sys.stderr)
            continue

        for run in data.get("runs", []):
            # Rules are declared once at the top of each run
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rid = rule.get("id", "")
                if not rid:
                    continue
                props = rule.get("properties", {}) or {}
                rule_meta[rid] = {
                    "name": rule.get("shortDescription", {}).get("text") or rule.get("name") or rid,
                    "description": (rule.get("fullDescription", {}) or {}).get("text", ""),
                    "severity_score": float(props.get("security-severity", 0) or 0),
                }

            for result in run.get("results", []):
                rid = result.get("ruleId", "")
                if not rid:
                    continue
                # Skip diagnostic / non-attributable noise
                if rule_meta.get(rid, {}).get("severity_score", 0) == 0 and rid.startswith("cs/diagnostics"):
                    continue
                loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
                findings_by_rule[rid].append({
                    "file": (loc.get("artifactLocation") or {}).get("uri", ""),
                    "line": (loc.get("region") or {}).get("startLine", 0),
                    "message": (result.get("message") or {}).get("text", ""),
                    "level": result.get("level", ""),
                })
                total += 1

    # Build a list of categories, sorted by severity then count.
    categories: list[dict] = []
    for rid, findings in findings_by_rule.items():
        meta = rule_meta.get(rid, {})
        score = meta.get("severity_score", 0.0)
        # Take the worst level seen if no score
        worst_level = "note"
        for f in findings:
            if f["level"] == "error":
                worst_level = "error"; break
            if f["level"] == "warning":
                worst_level = "warning"
        sev = severity_bucket(score, worst_level)

        ckey = category_key(rid)
        categories.append({
            "rule_id": rid,
            "title": human_category(rid),
            "name": meta.get("name") or rid,
            "severity": sev,
            "score": score,
            "count": len(findings),
            "explanation": CATEGORY_DESCRIPTIONS.get(ckey, meta.get("description", "")[:240]),
            "files": sorted({f["file"] for f in findings if f["file"]})[:5],
            "examples": findings[:3],
        })

    # Sort: severity (Critical first), then by count desc
    categories.sort(key=lambda c: (SEVERITY_ORDER.index(c["severity"]), -c["count"]))

    out_path.write_text(render(categories, total, files), encoding="utf-8")
    print(f"Wrote {out_path}  ({total} findings across {len(categories)} categories)")
    return 0


def render(categories: list[dict], total: int, files: list[Path]) -> str:
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for c in categories:
        sev_counts[c["severity"]] += c["count"]

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if total == 0:
        verdict = ("✅", "#16a34a", "No security issues found",
                   "The scanner did not flag anything in this run.")
    elif sev_counts["Critical"] > 0:
        verdict = ("🚨", "#b91c1c", f"{sev_counts['Critical']} critical issue(s) need attention",
                   "Critical issues are likely exploitable. Fix these first.")
    elif sev_counts["High"] > 0:
        verdict = ("⚠️", "#ea580c", f"{sev_counts['High']} high-severity issue(s) found",
                   "Plan fixes for these in the current sprint.")
    elif sev_counts["Medium"] > 0:
        verdict = ("🟡", "#ca8a04", f"{sev_counts['Medium']} medium-severity issue(s) found",
                   "Real risk but limited blast radius. Schedule a fix.")
    else:
        verdict = ("🔵", "#0369a1", f"{total} low-severity issue(s) found",
                   "Hygiene items. Worth cleaning up over time.")

    summary_chips = "".join(
        f'<span class="chip" style="--c:{SEVERITY_COLOR[s]}">'
        f'<b>{sev_counts[s]}</b> {s}</span>'
        for s in SEVERITY_ORDER if sev_counts[s] > 0
    ) or '<span class="chip" style="--c:#16a34a"><b>0</b> issues</span>'

    cards_html = "\n".join(render_card(c) for c in categories) or render_empty()

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Scan Report</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    margin: 0; padding: 32px; max-width: 960px; margin-inline: auto;
    background: #f8fafc; color: #0f172a; line-height: 1.5;
  }}
  h1 {{ margin: 0 0 4px; font-size: 28px; }}
  .meta {{ color: #475569; font-size: 14px; margin-bottom: 24px; }}
  .verdict {{
    background: white; border-left: 6px solid var(--accent); border-radius: 8px;
    padding: 20px 24px; margin-bottom: 24px;
    box-shadow: 0 1px 2px rgba(0,0,0,.04);
  }}
  .verdict h2 {{ margin: 0 0 4px; font-size: 20px; }}
  .verdict p {{ margin: 0; color: #475569; }}
  .summary-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 32px; }}
  .chip {{
    background: white; border: 1px solid #e2e8f0; border-radius: 999px;
    padding: 6px 14px; font-size: 14px; color: #334155;
    border-left: 4px solid var(--c);
  }}
  .chip b {{ color: var(--c); margin-right: 4px; }}
  h2.section {{ font-size: 18px; margin: 0 0 12px; color: #334155; }}
  .card {{
    background: white; border-radius: 8px; padding: 18px 20px;
    margin-bottom: 12px; box-shadow: 0 1px 2px rgba(0,0,0,.04);
    border-left: 4px solid var(--sev);
  }}
  .card-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
  .card-title {{ font-size: 16px; font-weight: 600; margin: 0; }}
  .card-meta {{ display: flex; gap: 8px; align-items: center; }}
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 999px;
    font-size: 12px; font-weight: 600; color: white; background: var(--sev);
  }}
  .count {{
    background: #f1f5f9; color: #334155; padding: 2px 10px; border-radius: 999px;
    font-size: 12px; font-weight: 600;
  }}
  .desc {{ color: #475569; font-size: 14px; margin: 8px 0 6px; }}
  .files {{ font-size: 12px; color: #64748b; margin-top: 6px; }}
  .files code {{ background: #f1f5f9; padding: 1px 6px; border-radius: 4px; font-size: 12px; }}
  footer {{ margin-top: 32px; color: #94a3b8; font-size: 12px; text-align: center; }}
  @media print {{
    body {{ background: white; padding: 16px; }}
    .card, .verdict {{ box-shadow: none; border: 1px solid #e2e8f0; }}
  }}
</style>
</head>
<body>
  <h1>🛡️ Security Scan Report</h1>
  <div class="meta">CodeQL · generated {timestamp}</div>

  <div class="verdict" style="--accent:{verdict[1]}">
    <h2>{verdict[0]} {escape(verdict[2])}</h2>
    <p>{escape(verdict[3])}</p>
  </div>

  <div class="summary-row">{summary_chips}</div>

  <h2 class="section">Issues by category</h2>
  {cards_html}

  <footer>{total} total finding(s) across {len(categories)} categor{'y' if len(categories)==1 else 'ies'}.</footer>
</body>
</html>
"""


def render_empty() -> str:
    return ('<div class="card" style="--sev:#16a34a">'
            '<p class="desc">Nothing to report. The scanner did not flag any issues.</p>'
            '</div>')


def render_card(c: dict) -> str:
    color = SEVERITY_COLOR[c["severity"]]
    files_html = ""
    if c["files"]:
        items = " ".join(f"<code>{escape(f)}</code>" for f in c["files"])
        more = f" + {c['count'] - len(c['files'])} more occurrence(s)" if c["count"] > len(c["files"]) else ""
        files_html = f'<div class="files">Where: {items}{escape(more)}</div>'

    return f'''
  <div class="card" style="--sev:{color}">
    <div class="card-head">
      <h3 class="card-title">{escape(c["title"])}</h3>
      <div class="card-meta">
        <span class="badge">{c["severity"]}</span>
        <span class="count">{c["count"]} finding{'s' if c["count"] != 1 else ''}</span>
      </div>
    </div>
    <p class="desc">{escape(c["explanation"]) or "&nbsp;"}</p>
    {files_html}
  </div>'''


if __name__ == "__main__":
    raise SystemExit(main())
