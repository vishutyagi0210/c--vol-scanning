#!/usr/bin/env python3
"""
Turn a CodeQL SARIF file into a single-page, non-technical HTML report
grouped by vulnerability category and bucketed by severity.

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


# ---------- severity helpers -------------------------------------------------

def severity_bucket(score: float, level: str) -> str:
    """Map CodeQL's numeric security-severity (CVSS-style 0-10) to a label.
    Falls back to the SARIF level only if no numeric score is available."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return {"error": "High", "warning": "Medium", "note": "Low"}.get(level, "Info")


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLOR = {
    "Critical": "#b91c1c",
    "High":     "#ea580c",
    "Medium":   "#ca8a04",
    "Low":      "#0369a1",
    "Info":     "#475569",
}

# Plain-English descriptions for common CodeQL C# rule families.
# Key matches the last segment of the rule id (e.g. cs/sql-injection -> sql-injection).
CATEGORY_DESCRIPTIONS = {
    "sql-injection":            "User input flows into a database query. Attackers can read, modify, or destroy data.",
    "command-line-injection":   "User input flows into a shell command. Attackers can run arbitrary commands on the server.",
    "command-injection":        "User input flows into a shell command. Attackers can run arbitrary commands on the server.",
    "path-injection":           "User input controls a file path. Attackers can read or write files outside intended folders.",
    "path-combine":             "File-path building has a flaw where one segment can silently override another.",
    "xss":                      "User input is rendered in HTML without escaping. Attackers can run scripts in users' browsers.",
    "log-forging":              "Untrusted input is written to logs as-is. Attackers can fake log entries to confuse audits.",
    "unsafe-deserialization":   "Untrusted data is turned back into objects. Attackers can run arbitrary code.",
    "unsafe-deserialization-untrusted-input": "Untrusted data is turned back into objects. Attackers can run arbitrary code.",
    "url-redirection":          "User input controls a redirect target. Attackers can send users to malicious sites.",
    "unvalidated-url-redirection": "User input controls a redirect target. Attackers can send users to malicious sites.",
    "ssrf":                     "Server makes a network request to a URL the user controls. Attackers can reach internal systems.",
    "request-forgery":          "Server makes a network request to a URL the user controls. Attackers can reach internal systems.",
    "xxe":                      "XML parser allows external entities. Attackers can read local files or hit internal URLs.",
    "xml-external-entity":      "XML parser allows external entities. Attackers can read local files or hit internal URLs.",
    "insecure-dtd-handling":    "XML processing allows Document Type Definitions, which can fetch external data.",
    "missing-validation":       "Input from outside the system is used without being checked first.",
    "ecb-encryption":           "Encryption uses ECB mode, which leaks patterns in the data.",
    "weak-cryptographic-algorithm": "A weak or broken algorithm (e.g. MD5, SHA-1, DES) is used for security.",
    "weak-encryption":          "A weak or broken encryption algorithm is used.",
    "broken-cryptographic-algorithm": "A broken cryptographic algorithm is used.",
    "hard-coded-credentials":   "Passwords or keys are written directly in source code.",
    "hardcoded-credentials":    "Passwords or keys are written directly in source code.",
    "insecure-randomness":      "Randomness comes from a predictable source. Tokens or keys can be guessed.",
    "catch-of-all-exceptions":  "Code swallows every error, hiding real problems from monitoring.",
    "file-upload":              "Files uploaded from the network are accepted without sufficient checks.",
    "stack-trace-exposure":     "Internal error details are returned to users, helping attackers map the system.",
    "cleartext-storage":        "Sensitive data is stored without encryption.",
    "cleartext-logging":        "Sensitive data is written to logs in plain text.",
}


def human_category(rule_id: str, fallback: str = "") -> str:
    short = rule_id.split("/")[-1] or fallback
    return short.replace("-", " ").replace("_", " ").capitalize()


def category_key(rule_id: str) -> str:
    return rule_id.split("/")[-1]


# ---------- SARIF parsing ----------------------------------------------------

def collect_rules(run: dict) -> dict[str, dict]:
    """Build {rule_id -> rule dict} from both driver.rules and every
    tool.extensions[].rules. CodeQL puts its security rules in extensions."""
    rules: dict[str, dict] = {}
    tool = run.get("tool", {}) or {}

    def add(rule_list):
        for rule in rule_list or []:
            rid = rule.get("id")
            if rid:
                rules[rid] = rule

    add((tool.get("driver") or {}).get("rules"))
    for ext in tool.get("extensions") or []:
        add(ext.get("rules"))
    return rules


def rule_score(rule: dict, result: dict) -> float:
    """Pull security-severity from the rule first, then the result as a fallback."""
    for src in (rule.get("properties") or {}, result.get("properties") or {}):
        v = src.get("security-severity")
        if v is not None:
            try:
                return float(v)
            except (TypeError, ValueError):
                pass
    return 0.0


def rule_default_level(rule: dict) -> str:
    return ((rule.get("defaultConfiguration") or {}).get("level")) or "warning"


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
    out_path.parent.mkdir(parents=True, exist_ok=True)

    files = collect_sarif_files(src)
    if not files:
        print(f"No SARIF files found at {src}", file=sys.stderr)
        out_path.write_text(render([], 0, []), encoding="utf-8")
        return 0

    findings_by_rule: dict[str, list[dict]] = defaultdict(list)
    rule_meta: dict[str, dict] = {}
    total = 0

    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Skipping {f}: {e}", file=sys.stderr)
            continue

        for run in data.get("runs", []):
            rules = collect_rules(run)

            for result in run.get("results", []):
                rid = result.get("ruleId") or ""
                if not rid:
                    continue

                rule = rules.get(rid, {})

                # Skip CodeQL's own diagnostic / extraction noise
                tags = ((rule.get("properties") or {}).get("tags")) or []
                if "internal" in tags or "non-attributable" in tags or rid.startswith("cs/diagnostics") or "diagnostic" in (rule.get("properties") or {}).get("kind", ""):
                    continue

                score = rule_score(rule, result)
                level = result.get("level") or rule_default_level(rule)

                if rid not in rule_meta:
                    rule_meta[rid] = {
                        "name": (rule.get("shortDescription") or {}).get("text") or rule.get("name") or rid,
                        "description": (rule.get("fullDescription") or {}).get("text", ""),
                        "score": score,
                        "level": level,
                    }

                loc = (result.get("locations") or [{}])[0].get("physicalLocation", {}) or {}
                findings_by_rule[rid].append({
                    "file": (loc.get("artifactLocation") or {}).get("uri", ""),
                    "line": (loc.get("region") or {}).get("startLine", 0),
                    "message": (result.get("message") or {}).get("text", ""),
                    "level": level,
                    "score": score,
                })
                total += 1

    categories: list[dict] = []
    for rid, findings in findings_by_rule.items():
        meta = rule_meta[rid]
        score = meta["score"]
        level = meta["level"]
        sev = severity_bucket(score, level)

        ckey = category_key(rid)
        categories.append({
            "rule_id": rid,
            "title": meta["name"],
            "severity": sev,
            "score": score,
            "count": len(findings),
            "explanation": CATEGORY_DESCRIPTIONS.get(ckey, (meta["description"] or "").strip()[:240]),
            "files": sorted({f["file"] for f in findings if f["file"]})[:5],
        })

    # Sort: severity (Critical first), then by count desc, then by title.
    categories.sort(key=lambda c: (SEVERITY_ORDER.index(c["severity"]), -c["count"], c["title"]))

    out_path.write_text(render(categories, total, files), encoding="utf-8")
    print(f"Wrote {out_path}  ({total} findings across {len(categories)} categories)")
    # Diagnostic dump so you can see the bucketing in the workflow log
    for c in categories:
        print(f"  [{c['severity']:8s}] score={c['score']:>4} count={c['count']:>3}  {c['rule_id']}")
    return 0


# ---------- HTML rendering ---------------------------------------------------

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
        f'<span class="chip" style="--c:{SEVERITY_COLOR[s]}"><b>{sev_counts[s]}</b> {s}</span>'
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

    score_label = f" · score {c['score']:.1f}" if c["score"] > 0 else ""

    return f'''
  <div class="card" style="--sev:{color}">
    <div class="card-head">
      <h3 class="card-title">{escape(c["title"])}</h3>
      <div class="card-meta">
        <span class="badge">{c["severity"]}{escape(score_label)}</span>
        <span class="count">{c["count"]} finding{'s' if c["count"] != 1 else ''}</span>
      </div>
    </div>
    <p class="desc">{escape(c["explanation"]) or "&nbsp;"}</p>
    {files_html}
  </div>'''


if __name__ == "__main__":
    raise SystemExit(main())
