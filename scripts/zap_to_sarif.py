#!/usr/bin/env python3
"""
Convert a ZAP JSON report (-J) into SARIF 2.1.0 so DAST findings land in the
same place as SAST/SCA: GitHub code scanning + the security gate.

GitHub code scanning needs a file location, so every DAST result is anchored to
a repo file (the OpenAPI spec by default) and the URL goes in the message.

Usage: zap_to_sarif.py zap.json out.sarif --anchor demo-app/openapi.json
"""
import argparse
import hashlib
import html
import json
import re

RISK = {  # ZAP riskcode -> (SARIF level, security-severity)
    "3": ("error", "8.0"),
    "2": ("warning", "5.5"),
    "1": ("note", "3.0"),
    "0": ("note", "0.0"),
}


def strip_html(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text or "")).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("zap_json")
    ap.add_argument("out_sarif")
    ap.add_argument("--anchor", default="openapi.json", help="repo file to attach results to")
    args = ap.parse_args()

    with open(args.zap_json, encoding="utf-8") as fh:
        zap = json.load(fh)

    rules, results = {}, []
    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            rule_id = f"ZAP-{alert.get('pluginid', 'unknown')}"
            level, score = RISK.get(str(alert.get("riskcode", "1")), RISK["1"])
            cwe = alert.get("cweid")
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": alert.get("name") or alert.get("alert"),
                "shortDescription": {"text": alert.get("name") or alert.get("alert", rule_id)},
                "fullDescription": {"text": strip_html(alert.get("desc"))[:1000]},
                "help": {"text": strip_html(alert.get("solution"))[:1000]},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": score,
                    "tags": ["security", "dast"] + ([f"external/cwe/cwe-{cwe}"] if cwe and cwe != "-1" else []),
                },
            })
            for inst in alert.get("instances", []) or [{}]:
                method, uri, param = inst.get("method", ""), inst.get("uri", ""), inst.get("param", "")
                msg = f"{alert.get('name')}: {method} {uri}"
                if param:
                    msg += f" (param: {param})"
                if inst.get("evidence"):
                    msg += f" | evidence: {inst['evidence'][:120]}"
                fp = hashlib.sha256(f"{rule_id}|{method}|{uri.split('?')[0]}|{param}".encode()).hexdigest()
                results.append({
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": msg},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": args.anchor},
                        "region": {"startLine": 1},
                    }}],
                    "partialFingerprints": {"zapFinding/v1": fp},
                })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ZAP",
                "informationUri": "https://www.zaproxy.org/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    with open(args.out_sarif, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    print(f"Converted {len(results)} ZAP instances across {len(rules)} rules -> {args.out_sarif}")


if __name__ == "__main__":
    main()
