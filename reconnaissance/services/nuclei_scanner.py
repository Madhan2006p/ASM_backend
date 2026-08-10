import json
from urllib.parse import urlparse

from attacksurface.scanner.vulnerability_scanner import run_python_vuln_scanner
from .command_utils import dedupe_preserve_order


def run_nuclei(targets):
    normalized_targets = normalize_targets(targets)

    if not normalized_targets:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "error": "No scan targets were provided",
            },
        }

    httpx_items = [{"url": t if t.startswith("http") else f"https://{t}", "headers": {}, "status_code": 0} for t in normalized_targets]
    target_host = urlparse(httpx_items[0]["url"]).hostname or normalized_targets[0]

    python_vulns = run_python_vuln_scanner(target_host, httpx_items)

    formatted_vulns = []
    for item in python_vulns:
        formatted_vulns.append({
            "template_id": item.get("template_id"),
            "name": item.get("finding"),
            "severity": item.get("severity", "info").lower(),
            "type": "http",
            "protocol": "http",
            "target": item.get("subdomain"),
            "host": item.get("subdomain"),
            "timestamp": "",
        })

    raw_output = json.dumps(formatted_vulns)
    parsed_output = {
        "total_vulnerabilities": len(formatted_vulns),
        "vulnerabilities": formatted_vulns,
        "targets_scanned": normalized_targets,
    }

    return {
        "raw_output": raw_output,
        "parsed_output": parsed_output,
    }


def normalize_targets(targets):
    if isinstance(targets, str):
        values = [targets.strip()]
    else:
        values = [item.strip() for item in targets or [] if item]

    return dedupe_preserve_order(values)

