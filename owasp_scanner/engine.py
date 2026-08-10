"""OWASP Top 10 scan engine.

Runs every detector (A01–A10) against the target and returns findings that
match the schema used by the attack-surface vulnerability scanner, with each
finding tagged with its OWASP category + rank.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .detectors.base import HTTPClient
from .owasp_categories import OWASP_CATEGORIES

logger = logging.getLogger(__name__)

from .detectors import (
    a01_broken_access_control,
    a02_cryptographic_failures,
    a03_injection,
    a04_insecure_design,
    a05_security_misconfiguration,
    a06_outdated_components,
    a07_auth_failures,
    a08_integrity_failures,
    a09_logging_monitoring,
    a10_ssrf,
)

# Order matters — categories display in this order on the dashboard
DETECTORS = [
    a01_broken_access_control.detect_a01,
    a02_cryptographic_failures.detect_a02,
    a03_injection.detect_a03,
    a04_insecure_design.detect_a04,
    a05_security_misconfiguration.detect_a05,
    a06_outdated_components.detect_a06,
    a07_auth_failures.detect_a07,
    a08_integrity_failures.detect_a08,
    a09_logging_monitoring.detect_a09,
    a10_ssrf.detect_a10,
]


def build_target_urls(domain, live_urls=None, max_urls=8):
    """Build a deduplicated list of probe URLs for the target."""
    urls = []
    seen = set()
    candidates = list(live_urls or [])
    candidates.append(f"https://{domain}")
    candidates.append(f"http://{domain}")
    for u in candidates:
        if not u:
            continue
        u = u.strip()
        if not u.startswith(("http://", "https://")):
            u = f"https://{u}"
        try:
            parsed = urlparse(u)
            hostname = (parsed.hostname or "").lower()
            if not hostname:
                continue
        except Exception:
            continue
        key = (hostname, parsed.scheme)
        if key in seen:
            continue
        seen.add(key)
        urls.append(u)
        if len(urls) >= max_urls:
            break
    return urls


def run_owasp_top10_scan(domain, live_urls=None, progress_cb=None):
    """Run all OWASP Top 10 detectors against a domain.

    Returns a dict:
      {"findings": [...], "categories": [{rank, id, name, count, findings}...],
       "total": int, "target": domain}
    """
    target_urls = build_target_urls(domain, live_urls)
    findings = []
    errors = []

    def run_one(detector):
        fn = detector
        category_label = fn.__module__.split(".")[-1]
        try:
            with HTTPClient() as http:
                return fn(domain, domain, target_urls, http) or []
        except Exception as exc:
            logger.exception("OWASP detector %s failed for %s: %s", category_label, domain, exc)
            return []

    with ThreadPoolExecutor(max_workers=min(8, len(DETECTORS))) as pool:
        futures = {pool.submit(run_one, d): d for d in DETECTORS}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                findings.extend(fut.result() or [])
            except Exception as exc:
                errors.append(str(exc))
            if progress_cb:
                try:
                    progress_cb(done, len(DETECTORS))
                except Exception:
                    pass

    # De-dup by (vulnerability_id, subdomain)
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("vulnerability_id"), f.get("subdomain"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    # Group by category for the API response
    categories = []
    for cat in OWASP_CATEGORIES:
        cat_findings = [f for f in unique if (f.get("owasp_rank") or 0) == cat["rank"]]
        categories.append({
            "rank": cat["rank"],
            "id": cat["id"],
            "name": cat["name"],
            "title": cat["title"],
            "description": cat["description"],
            "url": cat["url"],
            "cwes": cat["cwes"],
            "count": len(cat_findings),
            "severities": {
                "critical": sum(1 for f in cat_findings if (f.get("severity") or "").upper() == "CRITICAL"),
                "high": sum(1 for f in cat_findings if (f.get("severity") or "").upper() == "HIGH"),
                "medium": sum(1 for f in cat_findings if (f.get("severity") or "").upper() == "MEDIUM"),
                "low": sum(1 for f in cat_findings if (f.get("severity") or "").upper() == "LOW"),
                "info": sum(1 for f in cat_findings if (f.get("severity") or "").upper() == "INFO"),
            },
            "findings": cat_findings,
        })

    logger.info(
        "OWASP Top 10 scan for %s complete: %d unique findings across %d categories",
        domain, len(unique), sum(1 for c in categories if c["count"] > 0),
    )

    return {
        "target": domain,
        "findings": unique,
        "categories": categories,
        "total": len(unique),
        "errors": errors,
    }


def save_owasp_findings(scan, findings, domain):
    """Persist OWASP findings to VulnerabilityResult (deduped per scan).

    Dedup key mirrors deep_nuclei_scan._save_vuln: (template_id, subdomain).
    This makes OWASP findings collide with the Python scanner's equivalent
    findings (same template_id) instead of creating duplicates.

    Self-healing: after saving, OWASP findings from an EARLIER scan run that
    are no longer detected (e.g. a false positive suppressed by a detector
    guard) are deleted, so re-scans don't leave stale findings behind.
    """
    from attacksurface.models import VulnerabilityResult

    saved = 0
    current_keys = set()
    for f in findings:
        template_id = f.get("template_id") or f.get("vulnerability_id") or "owasp-vuln"
        vuln_id = f.get("vulnerability_id") or template_id
        host = f.get("subdomain") or domain
        current_keys.add((template_id, host))
        vr, created = VulnerabilityResult.objects.get_or_create(
            scan=scan,
            template_id=template_id,
            subdomain=host,
            defaults={
                "domain": domain,
                "vulnerability_id": vuln_id,
                "severity": str(f.get("severity") or "info").lower(),
                "cve": f.get("cve", ""),
                "cwe": f.get("cwe", ""),
                "finding": f.get("finding") or "OWASP Top 10 Finding",
                "description": f.get("description", ""),
                "remediation": f.get("remediation", ""),
                "reference": f.get("reference", ""),
                "source_tool": "OWASP Top 10",
                "owasp_category": f.get("owasp_category", ""),
                "owasp_rank": f.get("owasp_rank", 0),
                "confidence": f.get("confidence", 0.7),
                "finding_status": f.get("status", "potential"),
                "evidence": f.get("evidence", ""),
                "org_id": scan.org_id,
            },
        )
        if created:
            saved += 1
        else:
            # Refresh OWASP classification + VulnMap metadata on re-scans
            changed = False
            if f.get("owasp_category") and vr.owasp_category != f["owasp_category"]:
                vr.owasp_category = f["owasp_category"]
                changed = True
            if f.get("owasp_rank") and vr.owasp_rank != f["owasp_rank"]:
                vr.owasp_rank = f["owasp_rank"]
                changed = True
            if f.get("confidence") is not None and vr.confidence != f["confidence"]:
                vr.confidence = f["confidence"]
                changed = True
            if f.get("status") and vr.finding_status != f["status"]:
                vr.finding_status = f["status"]
                changed = True
            if f.get("evidence") and vr.evidence != f["evidence"]:
                vr.evidence = f["evidence"]
                changed = True
            if changed:
                vr.save(update_fields=["owasp_category", "owasp_rank", "confidence", "finding_status", "evidence"])

    # Self-healing cleanup: drop OWASP findings from previous runs that the
    # current run no longer produces (template_id + subdomain not re-detected).
    if current_keys:
        stale_rows = VulnerabilityResult.objects.filter(
            scan=scan, source_tool="OWASP Top 10"
        )
        stale_ids = [
            v.id for v in stale_rows
            if (v.template_id, v.subdomain) not in current_keys
        ]
        if stale_ids:
            VulnerabilityResult.objects.filter(id__in=stale_ids).delete()
    return saved
