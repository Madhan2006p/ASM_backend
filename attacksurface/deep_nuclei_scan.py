"""
Deep Nuclei Scan Engine
-----------------------
Runs Nuclei across ALL template categories in ordered phases.
• Saves each vulnerability to DB as soon as it is found (real-time streaming).
• Tracks current phase, progress, and estimated time on the AttackSurfaceScan model.
• Can run for up to 5 days total.
• Deduplicates by (template_id, matched_url) to avoid re-saving the same finding.
"""

import json
import logging
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


def _resolve_nuclei_binary():
    """Locate the nuclei binary: env var → Django settings → PATH → legacy path."""
    env_path = os.environ.get("NUCLEI_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    settings_path = getattr(settings, "NUCLEI_PATH", None)
    if settings_path and os.path.isfile(settings_path):
        return settings_path
    which = shutil.which("nuclei")
    if which:
        return which
    legacy = "/usr/bin/nuclei"
    if os.path.isfile(legacy):
        return legacy
    return None


def _resolve_template_root():
    """Locate nuclei templates dir: env var → Django settings → ~/nuclei-templates → legacy path."""
    env_tpl = os.environ.get("NUCLEI_TEMPLATES_PATH")
    if env_tpl and os.path.isdir(env_tpl):
        return env_tpl
    settings_tpl = getattr(settings, "NUCLEI_TEMPLATES_PATH", None)
    if settings_tpl and os.path.isdir(settings_tpl):
        return settings_tpl
    home_tpl = str(Path.home() / "nuclei-templates")
    if os.path.isdir(home_tpl):
        return home_tpl
    legacy = "/home/madhan/nuclei-templates"
    if os.path.isdir(legacy):
        return legacy
    return None


# Resolve at import time so SCAN_PHASES can build real template paths.
NUCLEI_PATH = _resolve_nuclei_binary() or "/usr/bin/nuclei"
TEMPLATE_ROOT = _resolve_template_root() or "/home/madhan/nuclei-templates"

# ── Phase definitions ──────────────────────────────────────────────────────────
# Each phase has: name, template paths, severity filter, rate-limit, est. hours
SCAN_PHASES = [
    {
        "id": "exposures",
        "name": "Exposed Files & Panels",
        "paths": [
            f"{TEMPLATE_ROOT}/http/exposures",
            f"{TEMPLATE_ROOT}/http/exposed-panels",
        ],
        "severity": "info,low,medium,high,critical",
        "rl": 60,
        "est_hours": 1.5,
    },
    {
        "id": "misconfiguration",
        "name": "Misconfigurations",
        "paths": [f"{TEMPLATE_ROOT}/http/misconfiguration"],
        "severity": "info,low,medium,high,critical",
        "rl": 50,
        "est_hours": 2.0,
    },
    {
        "id": "default_logins",
        "name": "Default Credentials",
        "paths": [f"{TEMPLATE_ROOT}/http/default-logins"],
        "severity": "medium,high,critical",
        "rl": 30,
        "est_hours": 1.0,
    },
    {
        "id": "takeovers",
        "name": "Subdomain Takeovers",
        "paths": [f"{TEMPLATE_ROOT}/http/takeovers"],
        "severity": "info,medium,high,critical",
        "rl": 50,
        "est_hours": 0.5,
    },
    {
        "id": "vulnerabilities",
        "name": "Known Web Vulnerabilities",
        "paths": [f"{TEMPLATE_ROOT}/http/vulnerabilities"],
        "severity": "medium,high,critical",
        "rl": 40,
        "est_hours": 3.0,
    },
    {
        "id": "cnvd",
        "name": "CNVD Database",
        "paths": [f"{TEMPLATE_ROOT}/http/cnvd"],
        "severity": "medium,high,critical",
        "rl": 40,
        "est_hours": 1.0,
    },
    {
        "id": "cves_recent",
        "name": "Recent CVEs (2022-2025)",
        "paths": [
            f"{TEMPLATE_ROOT}/http/cves/2025",
            f"{TEMPLATE_ROOT}/http/cves/2024",
            f"{TEMPLATE_ROOT}/http/cves/2023",
            f"{TEMPLATE_ROOT}/http/cves/2022",
        ],
        "severity": "medium,high,critical",
        "rl": 60,
        "est_hours": 6.0,
    },
    {
        "id": "cves_older",
        "name": "Historical CVEs (2015-2021)",
        "paths": [
            f"{TEMPLATE_ROOT}/http/cves/2021",
            f"{TEMPLATE_ROOT}/http/cves/2020",
            f"{TEMPLATE_ROOT}/http/cves/2019",
            f"{TEMPLATE_ROOT}/http/cves/2018",
            f"{TEMPLATE_ROOT}/http/cves/2017",
            f"{TEMPLATE_ROOT}/http/cves/2016",
            f"{TEMPLATE_ROOT}/http/cves/2015",
        ],
        "severity": "medium,high,critical",
        "rl": 60,
        "est_hours": 12.0,
    },
    {
        "id": "dns_network",
        "name": "DNS & Network Issues",
        "paths": [f"{TEMPLATE_ROOT}/dns", f"{TEMPLATE_ROOT}/network"],
        "severity": "info,low,medium,high,critical",
        "rl": 80,
        "est_hours": 1.0,
    },
    {
        "id": "iot",
        "name": "IoT & Industrial Devices",
        "paths": [f"{TEMPLATE_ROOT}/http/iot"],
        "severity": "medium,high,critical",
        "rl": 30,
        "est_hours": 1.0,
    },
]


# ── State tracking model (in-memory + DB) ─────────────────────────────────────

# This dict tracks the live state of any running deep scan per scan_id
# { scan_id: { "phase_idx": int, "phase_name": str, "started_at": datetime,
#              "total_found": int, "stop": bool } }
_LIVE_STATE = {}
_STATE_LOCK = threading.Lock()


def get_live_state(scan_id):
    with _STATE_LOCK:
        return _LIVE_STATE.get(scan_id, {}).copy()


def _set_live_state(scan_id, **kwargs):
    with _STATE_LOCK:
        if scan_id not in _LIVE_STATE:
            _LIVE_STATE[scan_id] = {}
        _LIVE_STATE[scan_id].update(kwargs)


def stop_deep_scan(scan_id):
    """Signal the running deep scan thread to stop cleanly."""
    with _STATE_LOCK:
        if scan_id in _LIVE_STATE:
            _LIVE_STATE[scan_id]["stop"] = True


# ── DB helper ──────────────────────────────────────────────────────────────────

def _save_vuln(scan, finding, domain):
    """Save a single vulnerability to the DB if it hasn't been saved yet."""
    from .models import VulnerabilityResult

    template_id = finding.get("template_id") or finding.get("template-id") or ""
    target = finding.get("target") or finding.get("matched-at") or ""
    name = finding.get("name", "")
    severity = finding.get("severity", "unknown").lower()
    description = finding.get("description", "")
    remediation = finding.get("remediation", "")
    reference = finding.get("reference", "")
    if isinstance(reference, list):
        reference = "\n".join(reference)

    # Deduplicate check
    if VulnerabilityResult.objects.filter(scan=scan, template_id=template_id, subdomain=target).exists():
        return False

    VulnerabilityResult.objects.create(
        scan=scan,
        vulnerability_id=template_id,
        domain=domain,
        subdomain=target,
        severity=severity,
        finding=name,
        description=description,
        remediation=remediation,
        reference=reference,
        template_id=template_id,
        source_tool="Nuclei-DeepScan",
        org_id=scan.org_id,
    )
    return True


# ── Core scanner ───────────────────────────────────────────────────────────────

def _run_phase_streaming(scan_id, scan, domain, targets, phase, phase_idx):
    """
    Run a single nuclei phase, streaming results to DB line-by-line as they arrive.
    Returns count of vulnerabilities found in this phase.
    """
    found_count = 0
    phase_name = phase["name"]

    # Only include paths that actually exist
    import os
    valid_paths = [p for p in phase["paths"] if os.path.exists(p)]
    if not valid_paths:
        logger.warning("Phase %s: no valid template paths under %s, skipping.",
                       phase_name, TEMPLATE_ROOT)
        return 0

    # Re-resolve the binary in case it became available after import time.
    nuclei_bin = _resolve_nuclei_binary()
    if not nuclei_bin:
        logger.error("Nuclei binary not found — cannot run phase '%s'.", phase_name)
        return 0

    cmd = [
        nuclei_bin,
        "-j",                          # JSON output, one line per finding
        "-severity", phase["severity"],
        "-rl", str(phase["rl"]),       # rate limit
        "-timeout", "10",
        "-retries", "1",
        "-duc",                        # disable update check
        "-ni",                         # no interactsh
        "-nc",                         # no colour
        "-silent",
    ]

    # Add template paths
    for p in valid_paths:
        cmd += ["-t", p]

    # Add targets
    if len(targets) == 1:
        cmd += ["-u", targets[0]]
    else:
        import tempfile
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tf.write("\n".join(targets))
        tf.close()
        cmd += ["-l", tf.name]

    logger.info("Starting nuclei phase '%s' for scan %s | cmd: %s", phase_name, scan_id, " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        for line in proc.stdout:
            # Check if we've been asked to stop
            state = get_live_state(scan_id)
            if state.get("stop"):
                proc.terminate()
                logger.info("Deep scan %s was stopped during phase '%s'", scan_id, phase_name)
                return found_count

            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Parse the nuclei JSON finding
            finding = {
                "template_id": data.get("template-id", ""),
                "name": data.get("info", {}).get("name", ""),
                "severity": data.get("info", {}).get("severity", "unknown"),
                "target": data.get("matched-at") or data.get("url") or data.get("host", ""),
                "description": data.get("info", {}).get("description", ""),
                "remediation": data.get("info", {}).get("remediation", ""),
                "reference": data.get("info", {}).get("reference", []),
            }

            try:
                saved = _save_vuln(scan, finding, domain)
                if saved:
                    found_count += 1
                    new_total = get_live_state(scan_id).get("total_found", 0) + 1
                    _set_live_state(scan_id, total_found=new_total)
                    # Persist found count to DB so it survives restarts
                    try:
                        scan.__class__.objects.filter(pk=scan.pk).update(nuclei_found=new_total)
                    except Exception:
                        pass
                    logger.info("  [+] Found: %s (%s) → %s", finding["name"], finding["severity"], finding["target"])
            except Exception as e:
                logger.warning("Failed to save finding: %s", e)

        proc.wait(timeout=60)

    except Exception as e:
        logger.exception("Error during nuclei phase '%s': %s", phase_name, e)

    return found_count


# ── Main orchestrator ──────────────────────────────────────────────────────────

def run_deep_nuclei_scan(scan_id, domain, targets):
    """
    Main entry point. Runs all phases sequentially, updating live state.
    Designed to be launched in a background thread.
    """
    from .models import AttackSurfaceScan

    try:
        scan = AttackSurfaceScan.objects.get(id=scan_id)
    except AttackSurfaceScan.DoesNotExist:
        logger.error("Deep scan: scan %s not found.", scan_id)
        return

    total_phases = len(SCAN_PHASES)
    total_found = 0

    _set_live_state(scan_id,
        phase_idx=0,
        phase_name=SCAN_PHASES[0]["name"],
        started_at=datetime.now().isoformat(),
        total_found=0,
        stop=False,
        status="running",
        total_phases=total_phases,
    )

    logger.info("=== Deep Nuclei Scan STARTED for %s (scan_id=%s) ===", domain, scan_id)
    logger.info("Total phases: %d | Total templates: 13,235+", total_phases)

    for idx, phase in enumerate(SCAN_PHASES):
        state = get_live_state(scan_id)
        if state.get("stop"):
            break

        phase_start = time.time()

        # Calculate estimated time for remaining phases
        remaining_est_hours = sum(p["est_hours"] for p in SCAN_PHASES[idx:])

        _set_live_state(scan_id,
            phase_idx=idx,
            phase_name=phase["name"],
            phase_id=phase["id"],
            phase_start=datetime.now().isoformat(),
            remaining_phases=total_phases - idx,
            remaining_est_hours=round(remaining_est_hours, 1),
            next_phase_name=SCAN_PHASES[idx + 1]["name"] if idx + 1 < total_phases else "Complete",
        )

        logger.info("--- Phase %d/%d: %s ---", idx + 1, total_phases, phase["name"])

        # Update vuln_scan_phase + persist nuclei_phase to DB so frontend can poll after restart
        scan.vuln_scan_phase = f"phase_{idx+1}_of_{total_phases}_{phase['id']}"
        scan.nuclei_phase = phase["name"]
        scan.save(update_fields=["vuln_scan_phase", "nuclei_phase", "updated_at"])

        phase_found = _run_phase_streaming(scan_id, scan, domain, targets, phase, idx)
        total_found += phase_found

        phase_elapsed = round((time.time() - phase_start) / 60, 1)
        logger.info("Phase '%s' done in %.1f min | Found: %d | Total so far: %d",
                    phase["name"], phase_elapsed, phase_found, total_found)

        _set_live_state(scan_id, total_found=total_found)

        # Stop check after each phase
        if get_live_state(scan_id).get("stop"):
            break

    # Mark complete
    scan.vuln_scan_phase = "complete"
    scan.nuclei_phase = "Scan Complete"
    scan.nuclei_found = total_found
    scan.vulnerabilities_done = True
    scan.save(update_fields=["vuln_scan_phase", "nuclei_phase", "nuclei_found", "vulnerabilities_done", "updated_at"])

    _set_live_state(scan_id,
        status="complete",
        phase_name="Scan Complete",
        total_found=total_found,
        completed_at=datetime.now().isoformat(),
    )

    logger.info("=== Deep Nuclei Scan COMPLETE for %s | Total found: %d ===", domain, total_found)


def start_deep_scan_thread(scan_id, domain, targets):
    """Launch the deep scan in a daemon thread so it doesn't block the request."""
    t = threading.Thread(
        target=run_deep_nuclei_scan,
        args=(scan_id, domain, targets),
        daemon=True,
        name=f"deep-nuclei-{scan_id}",
    )
    t.start()
    logger.info("Deep nuclei scan thread started for scan_id=%s", scan_id)
    return t
