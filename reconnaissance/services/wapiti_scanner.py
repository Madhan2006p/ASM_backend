import json
from urllib.parse import urlparse

from attacksurface.scanner.vulnerability_scanner import run_python_vuln_scanner


def run_wapiti(targets, max_attack_time=60):
    """Run Python vulnerability scanner on given targets (replacing external Wapiti)."""
    if isinstance(targets, str):
        targets = [targets]

    targets = [t.strip() for t in (targets or []) if t and t.strip()]

    if not targets:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "error": "No valid targets provided for scan",
            },
        }

    httpx_items = [{"url": t if t.startswith("http") else f"https://{t}", "headers": {}, "status_code": 0} for t in targets]
    target_host = urlparse(httpx_items[0]["url"]).hostname or targets[0]

    all_vulnerabilities = run_python_vuln_scanner(target_host, httpx_items)

    return {
        "raw_output": json.dumps(all_vulnerabilities),
        "parsed_output": {
            "total_vulnerabilities": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "targets_scanned": targets,
        },
    }

