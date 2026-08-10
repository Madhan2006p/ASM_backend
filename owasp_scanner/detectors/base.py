"""Shared HTTP client + finding builder for OWASP Top 10 detectors."""

import logging
import re
import time
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(connect=3.0, read=6.0, write=5.0, pool=3.0)
USER_AGENT = "ASM-OWASP-Scanner/1.0 (Attack Surface Management)"

# Keys present on every detector finding (same schema as the python vuln scanner)
DETECTOR_FINDING_KEYS = [
    "vulnerability_id",
    "domain",
    "subdomain",
    "severity",
    "cve",
    "cwe",
    "finding",
    "description",
    "remediation",
    "reference",
    "template_id",
    "source_tool",
    "owasp_category",
    "owasp_rank",
]


def make_finding(domain, host, category, rank, vuln_id, severity, cwe,
                 finding, description, remediation, reference, template_id,
                 cve="", source_tool="OWASP Top 10", confidence=0.7,
                 status="potential", evidence=""):
    """Build a standardized finding dict tagged with its OWASP category.

    VulnMap enrichment:
      confidence — 0.0-1.0 how certain the detector is (probes/heuristics score
                   lower than direct observations)
      status     — "confirmed" | "potential" | "informational" | "not_testable".
                   Detectors should default to "potential" for heuristic checks
                   and only use "confirmed" when the observation is direct
                   (e.g. a missing header or a literal secret in the body).
      evidence   — the concrete observation that triggered the finding
                   (status code, header value, redirect target, matched pattern)
    """
    return {
        "vulnerability_id": vuln_id,
        "domain": domain,
        "subdomain": host,
        "severity": severity,
        "cve": cve,
        "cwe": cwe,
        "finding": finding,
        "description": description,
        "remediation": remediation,
        "reference": reference,
        "template_id": template_id,
        "source_tool": source_tool,
        "owasp_category": category,
        "owasp_rank": rank,
        "confidence": confidence,
        "status": status,
        "evidence": evidence,
    }


class HTTPClient:
    """Thread-friendly HTTP client wrapper used by all detectors."""

    def __init__(self, timeout=None, follow_redirects=True):
        self._client = httpx.Client(
            verify=False,
            timeout=timeout or DEFAULT_TIMEOUT,
            follow_redirects=follow_redirects,
            headers={"User-Agent": USER_AGENT},
        )

    def get(self, url, **kwargs):
        return self._client.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self._client.post(url, **kwargs)

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ── Header helpers ──────────────────────────────────────────────────────────

def header_map(response):
    """Return case-insensitive header dict from a response."""
    return {k.lower(): v for k, v in response.headers.items()}


def host_of(url, fallback=""):
    return urlparse(url).hostname or fallback
