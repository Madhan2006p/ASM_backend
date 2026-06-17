import json
import logging
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from .command_utils import (
    add_execution_error,
    combine_output,
    resolve_executable,
    run_command,
)

logger = logging.getLogger(__name__)

WAPITI_CANDIDATES = (
    r"C:\Python310\Scripts\wapiti.exe",
    r"C:\Python311\Scripts\wapiti.exe",
    r"C:\Python312\Scripts\wapiti.exe",
    r"C:\Users\samyu\AppData\Local\Programs\Python\Python312\Scripts\wapiti.exe",
)


def run_wapiti(targets, max_attack_time=60):
    """Run Wapiti 3 scanner on given targets and return vulnerabilities."""
    if isinstance(targets, str):
        targets = [targets]

    executable = resolve_executable(
        "wapiti",
        env_var="WAPITI_PATH",
        candidates=WAPITI_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "error": "wapiti executable was not found on this system",
            },
        }

    # Normalize to full URLs
    urls = []
    for t in targets[:3]:
        t = t.strip()
        if not t:
            continue
        if t.startswith("http://") or t.startswith("https://"):
            urls.append(t)
        else:
            urls.append(f"https://{t}")

    if not urls:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "error": "No valid URLs provided for wapiti scan",
            },
        }

    all_vulnerabilities = []
    all_raw = []

    for url in urls:
        logger.info("wapiti scanning %s", url)
        tmpdir = tempfile.mkdtemp(prefix="wapiti_")
        out_path = Path(tmpdir) / "report.json"
        try:
            args = [
                executable, "-u", url, "--scope", "folder",
                "-f", "json", "-o", str(out_path),
                "--max-attack-time", str(max_attack_time),
                "--max-scan-time", str(max_attack_time * 2),
                "--max-crawling-time", "60",
                "-S", "sneaky", "-t", "10", "--verify-ssl", "0", "--tasks", "5",
            ]
            execution = run_command(args, timeout=(max_attack_time * 3) + 30)
            all_raw.append(combine_output(execution["stdout"], execution["stderr"]))

            if out_path.exists():
                data = json.loads(out_path.read_text(encoding="utf-8"))
                report = data if isinstance(data, dict) else {}
                vuln_categories = report.get("vulnerabilities") or {}
                host = urlparse(url).hostname or url
                sev_map = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL"}
                seen_for_host = set()
                for category, items in vuln_categories.items():
                    for item in (items or []):
                        vuln_id = f"WAPITI-{category.upper()}"
                        dedup_key = (host, vuln_id)
                        if dedup_key in seen_for_host:
                            continue
                        seen_for_host.add(dedup_key)
                        finding = item.get("info") or category
                        raw_level = item.get("level", 1)
                        severity = sev_map.get(str(raw_level), "INFO")
                        all_vulnerabilities.append({
                            "vulnerability_id": vuln_id,
                            "domain": host,
                            "subdomain": host,
                            "severity": severity,
                            "cve": "",
                            "cwe": "",
                            "finding": f"{category}: {finding}",
                            "template_id": category,
                            "source_tool": "Wapiti",
                        })
                logger.info("wapiti found %d items for %s", len(all_vulnerabilities), url)
        except json.JSONDecodeError as e:
            logger.warning("wapiti JSON parse error for %s: %s", url, e)
        except Exception as e:
            logger.exception("wapiti failed for %s: %s", url, e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    raw_output = "\n---\n".join(all_raw)
    parsed_output = {
        "total_vulnerabilities": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities,
        "targets_scanned": urls,
    }

    return {
        "raw_output": raw_output,
        "parsed_output": parsed_output,
    }
