#!/usr/bin/env python3
"""
Turn one or more SARIF (or Gitleaks JSON) files into a single-page,
non-technical HTML report.

Tool-agnostic: works with any SARIF 2.1.0 producer (CodeQL, Semgrep, Trivy,
Snyk, Checkov, etc.) and also reads Gitleaks v8 JSON output as a special case.
Each tool gets a tag on its findings and everything is grouped by category
and sorted by severity.

Usage:
    python sarif_to_report.py <file-or-dir> [more files/dirs...] <output.html>
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path


# ---------- severity ---------------------------------------------------------

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLOR = {
    "Critical": "#b91c1c",
    "High":     "#ea580c",
    "Medium":   "#ca8a04",
    "Low":      "#0369a1",
    "Info":     "#475569",
}
LEVEL_TO_SEVERITY = {
    "error":   "High",
    "warning": "Medium",
    "note":    "Low",
    "none":    "Info",
}
TAG_TO_SEVERITY = {  # some tools (Trivy, Gitleaks) put severity in tags
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "moderate": "Medium",
    "low":      "Low",
    "info":     "Info",
    "informational": "Info",
}


def severity_from_score(score: float) -> str | None:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0.0:  return "Low"
    return None


def pick_severity(score: float, level: str, tags: list[str]) -> str:
    """CVSS-style score wins. Then SARIF level. Then tags. Then 'Info'."""
    sev = severity_from_score(score)
    if sev:
        return sev
    if level and level in LEVEL_TO_SEVERITY:
        return LEVEL_TO_SEVERITY[level]
    for t in tags or []:
        s = TAG_TO_SEVERITY.get(t.lower())
        if s:
            return s
    return "Info"


# ---------- SARIF helpers ----------------------------------------------------

def collect_rules(run: dict) -> dict[str, dict]:
    """Build {rule_id -> rule} from driver and every extension."""
    rules: dict[str, dict] = {}
    tool = run.get("tool", {}) or {}

    def add(lst):
        for r in lst or []:
            if r.get("id"):
                rules[r["id"]] = r

    add((tool.get("driver") or {}).get("rules"))
    for ext in tool.get("extensions") or []:
        add(ext.get("rules"))
    return rules


def get_score(rule: dict, result: dict) -> float:
    for src in ((result.get("properties") or {}), (rule.get("properties") or {})):
        v = src.get("security-severity")
        if v is None:
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            pass
    return 0.0


def get_tags(rule: dict, result: dict) -> list[str]:
    tags: list[str] = []
    for src in ((rule.get("properties") or {}), (result.get("properties") or {})):
        t = src.get("tags")
        if isinstance(t, list):
            tags.extend(str(x) for x in t)
    return tags


CWE_RE = re.compile(r"cwe[-/]?(\d+)", re.I)


def cwe_ids(tags: list[str]) -> list[str]:
    out = []
    for t in tags:
        m = CWE_RE.search(t)
        if m:
            cwe = f"CWE-{m.group(1)}"
            if cwe not in out:
                out.append(cwe)
    return out


def is_diagnostic(rule: dict, rule_id: str) -> bool:
    """Skip extractor-internal noise (CodeQL emits these)."""
    props = rule.get("properties") or {}
    tags = props.get("tags") or []
    if "internal" in tags or "non-attributable" in tags:
        return True
    if (props.get("kind") or "") == "diagnostic":
        return True
    if "/diagnostics/" in rule_id or rule_id.endswith("-message") or rule_id.endswith("-error"):
        return True
    return False


def humanise_id(rule_id: str) -> str:
    """Last segment, dashes/underscores to spaces, sentence-cased."""
    short = rule_id.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
    short = short.replace("-", " ").replace("_", " ").strip()
    return short[:1].upper() + short[1:] if short else rule_id


def short_text(s: str, n: int = 240) -> str:
    s = (s or "").strip().replace("\n", " ")
    s = re.sub(r"\s+", " ", s)
    return (s[: n - 1] + "…") if len(s) > n else s


# ---------- I/O --------------------------------------------------------------

def collect_input_files(args: list[str]) -> list[Path]:
    """Find SARIF and known JSON report files (Gitleaks) under each input path."""
    out: list[Path] = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            out.extend(sorted(p.rglob("*.sarif")))
            out.extend(sorted(p.rglob("gitleaks-report*.json")))
        elif p.is_file():
            out.append(p)
    return out


def gitleaks_json_to_runs(data) -> list[dict]:
    """Convert Gitleaks v8 JSON (flat list of findings) into SARIF-shaped runs."""
    if not isinstance(data, list):
        return []
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in data:
        rid = f.get("RuleID") or "gitleaks"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": f.get("Description") or rid},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["secret"]},
            }
        results.append({
            "ruleId": rid,
            "level": "error",
            "message": {"text": f.get("Description") or "Hardcoded secret detected"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("File") or ""},
                    "region": {"startLine": f.get("StartLine") or 0},
                }
            }],
        })
    return [{
        "tool": {"driver": {"name": "Gitleaks", "rules": list(rules.values())}},
        "results": results,
    }]


def load_runs(path: Path) -> list[dict]:
    """Read a file and return SARIF-shaped runs, regardless of source format."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Skipping {path}: {e}", file=sys.stderr)
        return []
    if isinstance(data, list):
        # Gitleaks JSON format
        return gitleaks_json_to_runs(data)
    if isinstance(data, dict):
        if "runs" in data:
            return data["runs"]
        # Some single-finding shapes — wrap so they fall through
        return []
    return []


# ---------- main -------------------------------------------------------------

def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    *inputs, out_arg = sys.argv[1:]
    out_path = Path(out_arg)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    files = collect_input_files(inputs)
    if not files:
        print(f"No report files found at {inputs}", file=sys.stderr)
        out_path.write_text(render([], 0, set(), {}), encoding="utf-8")
        return 0

    # Aggregate by (tool, rule_id) so multiple findings of the same rule from
    # the same tool collapse into one card.
    bucket: dict[tuple[str, str], dict] = {}
    total = 0
    tools_seen: set[str] = set()
    sev_counts = {s: 0 for s in SEVERITY_ORDER}

    for f in files:
        for run in load_runs(f):
            tool_name = ((run.get("tool") or {}).get("driver") or {}).get("name", "Unknown tool")
            tools_seen.add(tool_name)
            rules = collect_rules(run)

            for result in run.get("results", []):
                rid = result.get("ruleId") or ""
                if not rid:
                    continue
                rule = rules.get(rid, {})
                if is_diagnostic(rule, rid):
                    continue

                tags = get_tags(rule, result)
                score = get_score(rule, result)
                level = result.get("level") or ((rule.get("defaultConfiguration") or {}).get("level"))
                sev = pick_severity(score, level, tags)

                title = (
                    (rule.get("shortDescription") or {}).get("text")
                    or rule.get("name")
                    or humanise_id(rid)
                )
                desc = short_text(
                    (result.get("message") or {}).get("text")
                    or (rule.get("fullDescription") or {}).get("text")
                    or (rule.get("shortDescription") or {}).get("text")
                    or ""
                )
                loc = (result.get("locations") or [{}])[0].get("physicalLocation", {}) or {}
                file_uri = (loc.get("artifactLocation") or {}).get("uri") or ""
                line = (loc.get("region") or {}).get("startLine") or 0

                key = (tool_name, rid)
                entry = bucket.get(key)
                if entry is None:
                    entry = bucket[key] = {
                        "tool": tool_name,
                        "rule_id": rid,
                        "title": title,
                        "severity": sev,
                        "score": score,
                        "explanation": desc,
                        "cwes": cwe_ids(tags),
                        "files": set(),
                        "count": 0,
                    }
                else:
                    # Keep the worst severity ever seen for the rule
                    if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(entry["severity"]):
                        entry["severity"] = sev
                        entry["score"] = max(entry["score"], score)

                entry["count"] += 1
                if file_uri:
                    entry["files"].add(file_uri if not line else f"{file_uri}:{line}")
                sev_counts[sev] += 1
                total += 1

    # Finalise
    categories: list[dict] = []
    for c in bucket.values():
        c["files"] = sorted(c["files"])[:5]
        categories.append(c)
    categories.sort(key=lambda c: (
        SEVERITY_ORDER.index(c["severity"]),
        -c["count"],
        c["tool"],
        c["title"],
    ))

    out_path.write_text(render(categories, total, tools_seen, sev_counts), encoding="utf-8")
    print(f"Wrote {out_path}  ({total} findings across {len(categories)} categories from {len(tools_seen)} tool(s))")
    for c in categories:
        print(f"  [{c['severity']:8s}] {c['tool']:10s} count={c['count']:>3}  {c['rule_id']}")
    return 0


# ---------- HTML rendering ---------------------------------------------------

def render(categories: list[dict], total: int, tools: set[str], sev_counts: dict[str, int]) -> str:
    if not sev_counts:
        sev_counts = {s: 0 for s in SEVERITY_ORDER}

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tool_list = ", ".join(sorted(tools)) if tools else "no scanners"

    if total == 0:
        verdict = ("✅", "#16a34a", "No security issues found",
                   "The scanners did not flag anything in this run.")
    elif sev_counts.get("Critical", 0) > 0:
        verdict = ("🚨", "#b91c1c", f"{sev_counts['Critical']} critical issue(s) need attention",
                   "Critical issues are likely exploitable. Fix these first.")
    elif sev_counts.get("High", 0) > 0:
        verdict = ("⚠️", "#ea580c", f"{sev_counts['High']} high-severity issue(s) found",
                   "Plan fixes for these in the current sprint.")
    elif sev_counts.get("Medium", 0) > 0:
        verdict = ("🟡", "#ca8a04", f"{sev_counts['Medium']} medium-severity issue(s) found",
                   "Real risk but limited blast radius. Schedule a fix.")
    else:
        verdict = ("🔵", "#0369a1", f"{total} low-severity issue(s) found",
                   "Hygiene items. Worth cleaning up over time.")

    chips = "".join(
        f'<span class="chip" style="--c:{SEVERITY_COLOR[s]}"><b>{sev_counts.get(s, 0)}</b> {s}</span>'
        for s in SEVERITY_ORDER if sev_counts.get(s, 0) > 0
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
  .summary-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }}
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
  .card-meta {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }}
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 999px;
    font-size: 12px; font-weight: 600; color: white; background: var(--sev);
  }}
  .tool {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; color: #334155; background: #e2e8f0;
    text-transform: uppercase; letter-spacing: .03em;
  }}
  .cwe {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; color: #1e3a8a; background: #dbeafe;
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
  <div class="meta">Tools: {escape(tool_list)} · generated {timestamp}</div>

  <div class="verdict" style="--accent:{verdict[1]}">
    <h2>{verdict[0]} {escape(verdict[2])}</h2>
    <p>{escape(verdict[3])}</p>
  </div>

  <div class="summary-row">{chips}</div>

  <h2 class="section">Issues by category</h2>
  {cards_html}

  <footer>{total} total finding(s) across {len(categories)} categor{'y' if len(categories)==1 else 'ies'}.</footer>
</body>
</html>
"""


def render_empty() -> str:
    return ('<div class="card" style="--sev:#16a34a">'
            '<p class="desc">Nothing to report. The scanners did not flag any issues.</p>'
            '</div>')


def render_card(c: dict) -> str:
    color = SEVERITY_COLOR[c["severity"]]
    files_html = ""
    if c["files"]:
        items = " ".join(f"<code>{escape(f)}</code>" for f in c["files"])
        more = f" + {c['count'] - len(c['files'])} more occurrence(s)" if c["count"] > len(c["files"]) else ""
        files_html = f'<div class="files">Where: {items}{escape(more)}</div>'

    score_label = f" · {c['score']:.1f}" if c["score"] > 0 else ""
    cwe_html = " ".join(f'<span class="cwe">{escape(cwe)}</span>' for cwe in c["cwes"][:3])

    return f'''
  <div class="card" style="--sev:{color}">
    <div class="card-head">
      <h3 class="card-title">{escape(c["title"])}</h3>
      <div class="card-meta">
        <span class="tool">{escape(c["tool"])}</span>
        {cwe_html}
        <span class="badge">{c["severity"]}{escape(score_label)}</span>
        <span class="count">{c["count"]} finding{'s' if c["count"] != 1 else ''}</span>
      </div>
    </div>
    <p class="desc">{escape(c["explanation"]) or "&nbsp;"}</p>
    {files_html}
  </div>'''


if __name__ == "__main__":
    raise SystemExit(main())
