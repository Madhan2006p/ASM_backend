"""
Deep Python Vulnerability Scan Engine
------------------------------------
Runs Python-based vulnerability checks across structured phases.
• Saves each vulnerability to DB as soon as it is found (real-time streaming).
• Tracks current phase and progress on the AttackSurfaceScan model.
• Operates without external binaries (Nuclei/Wapiti).
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from .scanner.vulnerability_scanner import run_python_vuln_scanner

logger = logging.getLogger(__name__)

# ── Phase definitions ──────────────────────────────────────────────────────────
SCAN_PHASES = [
    {
        "id": "owasp_top10",
        "name": "OWASP Top 10 Assessment",
        "est_hours": 0.15,
    },
    {
        "id": "exposures",
        "name": "Exposed Files & Sensitive Endpoints",
        "est_hours": 0.1,
    },
    {
        "id": "misconfiguration",
        "name": "HTTP & Server Misconfigurations",
        "est_hours": 0.1,
    },
    {
        "id": "security_headers",
        "name": "Security Headers & Policies",
        "est_hours": 0.1,
    },
    {
        "id": "cookie_session",
        "name": "Cookie Flags & Session Security",
        "est_hours": 0.1,
    },
    {
        "id": "cors_methods",
        "name": "CORS & Dangerous HTTP Methods",
        "est_hours": 0.1,
    },
    {
        "id": "exposed_ports",
        "name": "Sensitive Network Ports & Services",
        "est_hours": 0.1,
    },
    {
        "id": "cve_enrichment",
        "name": "NVD CVE Correlation",
        "est_hours": 0.05,
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
    template_id = finding.get("template_id") or finding.get("vulnerability_id") or "python-vuln"
    target = finding.get("target") or finding.get("subdomain") or domain

    if VulnerabilityResult.objects.filter(scan=scan, template_id=template_id, subdomain=target).exists():
        return False

    VulnerabilityResult.objects.create(
        scan=scan,
        domain=domain,
        subdomain=target,
        vulnerability_id=finding.get("vulnerability_id") or template_id,
        template_id=template_id,
        finding=finding.get("finding") or finding.get("name") or "Vulnerability Discovered",
        severity=str(finding.get("severity") or "info").lower(),
        cve=finding.get("cve") or "",
        cwe=finding.get("cwe") or "",
        description=finding.get("description") or "",
        remediation=finding.get("remediation") or "",
        reference=finding.get("reference") or "",
        source_tool=finding.get("source_tool") or "PythonScanner",
        owasp_category=finding.get("owasp_category") or "",
        owasp_rank=finding.get("owasp_rank") or 0,
        confidence=finding.get("confidence", 0.7),
        finding_status=finding.get("status") or "potential",
        evidence=finding.get("evidence") or "",
    )
    return True


# ── Core scanner ───────────────────────────────────────────────────────────────

def _run_cve_enrichment_phase(scan_id, scan, domain):
    """Correlate detected technologies/versions with NVD CVEs.

    Reads the TechnologyResult rows already stored for this scan and queries
    NVD for each (tech, version) pair, storing real CVE findings (with CVSS
    score, severity and references) into VulnerabilityResult.
    """
    from .cve_enrichment import enrich_scan_with_technology_cves
    from .models import TechnologyResult

    try:
        tech_map = {}
        for tr in TechnologyResult.objects.filter(scan=scan):
            tech_map[tr.domain] = tr.technologies or []
        if not tech_map:
            logger.info("CVE enrichment: no technologies recorded for scan %s", scan_id)
            return 0
        count = enrich_scan_with_technology_cves(scan, tech_map, domain)
        if count:
            logger.info("CVE enrichment stored %d findings for scan %s", count, scan_id)
        return count
    except Exception as exc:
        logger.warning("CVE enrichment failed for scan %s: %s", scan_id, exc)
        return 0


def _run_owasp_top10_phase(scan_id, scan, domain, targets):
    """
    Run the OWASP Top 10 (A01-A10) engine and stream findings to the DB.
    Returns number of findings stored.
    """
    from owasp_scanner.engine import run_owasp_top10_scan, save_owasp_findings

    saved_count = 0
    try:
        logger.info("Starting OWASP Top 10 assessment for scan %s on %s", scan_id, domain)
        result = run_owasp_top10_scan(domain, live_urls=targets or None)
        findings = result.get("findings", [])
        if findings:
            saved_count = save_owasp_findings(scan, findings, domain)
            new_total = get_live_state(scan_id).get("total_found", 0) + saved_count
            _set_live_state(scan_id, total_found=new_total)
            try:
                scan.__class__.objects.filter(pk=scan.pk).update(nuclei_found=new_total)
            except Exception:
                pass
            logger.info("OWASP Top 10 phase stored %d findings for scan %s", saved_count, scan_id)
    except Exception as e:
        logger.exception("OWASP Top 10 phase failed for scan %s: %s", scan_id, e)
    return saved_count


def _run_phase_streaming(scan_id, scan, domain, targets, phase, phase_idx):
    """
    Run a single Python vuln scanner phase, streaming results to DB.
    Returns count of vulnerabilities found in this phase.
    """
    # OWASP Top 10 runs through its own engine (category-aware findings)
    if phase.get("id") == "owasp_top10":
        return _run_owasp_top10_phase(scan_id, scan, domain, targets)
    # NVD CVE correlation runs against stored TechnologyResult rows
    if phase.get("id") == "cve_enrichment":
        return _run_cve_enrichment_phase(scan_id, scan, domain)

    found_count = 0
    phase_name = phase["name"]

    httpx_items = []
    for t in (targets or [domain]):
        url_str = t if isinstance(t, str) and t.startswith("http") else f"https://{t}"
        httpx_items.append({"url": url_str, "headers": {}, "status_code": 0})

    logger.info("Starting Python scanner phase '%s' for scan %s on %d targets", phase_name, scan_id, len(httpx_items))

    try:
        findings = run_python_vuln_scanner(domain, httpx_items)
        for item in findings:
            state = get_live_state(scan_id)
            if state.get("stop"):
                return found_count

            # Filter items per phase if appropriate or save phase findings
            saved = _save_vuln(scan, item, domain)
            if saved:
                found_count += 1
                new_total = get_live_state(scan_id).get("total_found", 0) + 1
                _set_live_state(scan_id, total_found=new_total)
                try:
                    scan.__class__.objects.filter(pk=scan.pk).update(nuclei_found=new_total)
                except Exception:
                    pass
                logger.info("  [+] Found: %s (%s) → %s", item.get("finding"), item.get("severity"), item.get("subdomain"))
    except Exception as e:
        logger.exception("Error during Python scanner phase '%s': %s", phase_name, e)

    return found_count


# ── Main orchestrator ──────────────────────────────────────────────────────────

def run_deep_nuclei_scan(scan_id, domain, targets):
    """
    Main entry point for deep vulnerability scanning using pure Python engine.
    Updates live state so UI progress remains active.
    """
    from .models import AttackSurfaceScan, VulnerabilityResult

    globals()["VulnerabilityResult"] = VulnerabilityResult

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

    logger.info("=== Deep Python Vulnerability Scan STARTED for %s (scan_id=%s) ===", domain, scan_id)

    for idx, phase in enumerate(SCAN_PHASES):
        state = get_live_state(scan_id)
        if state.get("stop"):
            break

        phase_start = time.time()
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

        scan.vuln_scan_phase = f"phase_{idx+1}_of_{total_phases}_{phase['id']}"
        scan.nuclei_phase = phase["name"]
        scan.save(update_fields=["vuln_scan_phase", "nuclei_phase", "updated_at"])

        phase_found = _run_phase_streaming(scan_id, scan, domain, targets, phase, idx)
        total_found += phase_found

        phase_elapsed = round((time.time() - phase_start) / 60, 1)
        logger.info("Phase '%s' done in %.1f min | Found: %d | Total so far: %d",
                    phase["name"], phase_elapsed, phase_found, total_found)

        _set_live_state(scan_id, total_found=total_found)

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

    logger.info("=== Deep Python Vulnerability Scan COMPLETE for %s | Total found: %d ===", domain, total_found)


def start_deep_scan_thread(scan_id, domain, targets):
    """Launch the deep scan in a daemon thread."""
    t = threading.Thread(
        target=run_deep_nuclei_scan,
        args=(scan_id, domain, targets),
        daemon=True,
        name=f"deep-nuclei-{scan_id}",
    )
    t.start()
    logger.info("Deep nuclei scan thread started for scan_id=%s", scan_id)
    return t
