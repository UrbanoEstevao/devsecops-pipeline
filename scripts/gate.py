#!/usr/bin/env python3
"""
Security gate: reads every SARIF file produced by the pipeline, normalises
severities across tools, applies policy-as-code (thresholds + expiring
exceptions) and decides pass/fail.

Usage: gate.py --reports reports/ --policy policy/security-policy.yml
"""
import argparse
import datetime as dt
import fnmatch
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

SEVERITIES = ["critical", "high", "medium", "low", "info"]
LEVEL_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def cvss_bucket(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def result_severity(result: dict, rule: dict) -> str:
    """security-severity (CVSS-like) wins; fall back to SARIF level."""
    for props in (result.get("properties", {}), rule.get("properties", {})):
        score = props.get("security-severity")
        if score is not None:
            try:
                return cvss_bucket(float(score))
            except ValueError:
                pass
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    return LEVEL_MAP.get(level, "medium")


def result_location(result: dict) -> str:
    try:
        loc = result["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        line = loc.get("region", {}).get("startLine")
        return f"{uri}:{line}" if line else uri
    except (KeyError, IndexError):
        return "-"


def load_findings(reports: Path):
    findings = []
    tools = set()  # every tool that produced a report, even with 0 findings
    for sarif_file in sorted(reports.rglob("*.sarif")):
        doc = json.loads(sarif_file.read_text(encoding="utf-8"))
        for run in doc.get("runs", []):
            tool = run.get("tool", {}).get("driver", {})
            tool_name = tool.get("name", sarif_file.stem)
            tools.add(tool_name)
            rules = {r.get("id"): r for r in tool.get("rules", [])}
            for res in run.get("results", []):
                rule_id = res.get("ruleId") or "unknown"
                rule = rules.get(rule_id, {})
                findings.append({
                    "tool": tool_name,
                    "rule": rule_id,
                    "severity": result_severity(res, rule),
                    "location": result_location(res),
                    "message": (res.get("message", {}).get("text") or "").splitlines()[0][:140],
                })
    return findings, tools


def active_exceptions(policy: dict, today: dt.date):
    active, expired = [], []
    for exc in policy.get("exceptions", []) or []:
        expires = exc.get("expires")
        if expires and dt.date.fromisoformat(str(expires)) < today:
            expired.append(exc)
        else:
            active.append(exc)
    return active, expired


def is_excepted(finding: dict, exceptions: list) -> bool:
    for exc in exceptions:
        if exc.get("rule") and not fnmatch.fnmatch(finding["rule"], exc["rule"]):
            continue
        if exc.get("tool") and exc["tool"].lower() != finding["tool"].lower():
            continue
        if exc.get("path") and not fnmatch.fnmatch(finding["location"], exc["path"]):
            continue
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True, type=Path)
    ap.add_argument("--policy", required=True, type=Path)
    args = ap.parse_args()

    policy = yaml.safe_load(args.policy.read_text(encoding="utf-8")) or {}
    mode = policy.get("mode", "enforce")
    thresholds = policy.get("max_findings", {"critical": 0, "high": 0})
    overrides = {k.lower(): v for k, v in (policy.get("severity_override") or {}).items()}

    findings, tools = load_findings(args.reports)
    for f in findings:
        if f["tool"].lower() in overrides:
            f["severity"] = overrides[f["tool"].lower()]

    exceptions, expired = active_exceptions(policy, dt.date.today())
    counted = [f for f in findings if not is_excepted(f, exceptions)]
    waived = len(findings) - len(counted)

    totals = Counter(f["severity"] for f in counted)
    per_tool = defaultdict(Counter)
    for t in tools:  # show tools with zero findings too
        per_tool[t]
    for f in counted:
        per_tool[f["tool"]][f["severity"]] += 1

    violations = []
    for sev in SEVERITIES:
        limit = thresholds.get(sev, -1)
        if limit is not None and limit >= 0 and totals[sev] > limit:
            violations.append(f"{totals[sev]} {sev} findings (max allowed: {limit})")

    failed = bool(violations) and mode == "enforce"

    # ---- report ----------------------------------------------------------
    icon = "❌" if failed else ("⚠️" if violations else "✅")
    lines = [f"## {icon} Security gate: {'FAILED' if failed else 'PASSED'} (mode: `{mode}`)", ""]
    lines += ["| Tool | " + " | ".join(s.title() for s in SEVERITIES) + " |",
              "|---|" + "---|" * len(SEVERITIES)]
    for tool in sorted(per_tool):
        lines.append(f"| {tool} | " + " | ".join(str(per_tool[tool][s]) for s in SEVERITIES) + " |")
    lines.append("| **Total** | " + " | ".join(f"**{totals[s]}**" for s in SEVERITIES) + " |")
    lines.append("")
    if violations:
        lines += ["**Policy violations:**", *[f"- {v}" for v in violations], ""]
    if waived:
        lines.append(f"_{waived} finding(s) waived by active exceptions._")
    if expired:
        lines.append(f"⚠️ {len(expired)} exception(s) have **expired** and no longer apply: "
                     + ", ".join(e.get("rule", "?") for e in expired))
    top = [f for f in counted if f["severity"] in ("critical", "high")][:25]
    if top:
        lines += ["", "<details><summary>Critical/High findings</summary>", "",
                  "| Sev | Tool | Rule | Location |", "|---|---|---|---|"]
        lines += [f"| {f['severity']} | {f['tool']} | `{f['rule']}` | `{f['location']}` |" for f in top]
        lines += ["", "</details>"]

    report = "\n".join(lines)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
