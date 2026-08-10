"""A09:2021 – Security Logging and Monitoring Failures detector.

Observable indicators that a site likely lacks adequate logging/monitoring:
- No security/observability headers or SIEM-affiliated signatures
- Exposed internal logging or metrics endpoints (actuator, prometheus, status)
- Verbose 5xx error pages leaking internals (hampers triage + leaks info)
- Missing error handling surfaces
"""

import re
from urllib.parse import urlparse

from .base import make_finding

CATEGORY = "A09:2021 – Security Logging and Monitoring Failures"
RANK = 9

OBSERVABILITY_PATHS = [
    "/actuator", "/actuator/health", "/metrics", "/prometheus", "/status",
    "/server-status", "/health", "/healthz", "/debug", "/trace", "/_status",
]

VERBOSE_5XX_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"exception in thread",
    r"internal server error</h1>",
    r"<title>500 internal server error</title>",
    r"java\.lang\..*exception",
]


def detect_a09(domain, host, base_urls, http):
    findings = []
    seen = set()

    def add(finding):
        key = (finding["vulnerability_id"], finding["subdomain"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    # 1. Exposed observability / metrics endpoints (probed in parallel)
    import concurrent.futures
    obs_targets = [base.rstrip("/") + p for base in list(base_urls)[:4] for p in OBSERVABILITY_PATHS]

    def _probe_obs(url):
        from .base import HTTPClient
        try:
            with HTTPClient() as probe_http:
                r = probe_http.get(url, timeout=4)
            return url, r.status_code, (r.text or "").lower()
        except Exception:
            return url, None, ""

    for url, code, body in concurrent.futures.ThreadPoolExecutor(max_workers=8).map(_probe_obs, obs_targets):
        if code not in (200, 201):
            continue
        if any(p in body for p in ("not found", "404", "page not found")):
            continue
        path = urlparse(url).path
        if path in ("/metrics", "/prometheus") or path.startswith("/actuator") or (
            path in ("/health", "/healthz") and code == 200
        ):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A09-OBSERVABILITY-ENDPOINT",
                "MEDIUM", "CWE-778",
                f"Monitoring/metrics endpoint exposed: {url}",
                f"The endpoint {url} is publicly reachable. Unauthenticated metrics or "
                f"health endpoints can leak internals and are a sign of missing "
                f"monitoring controls.",
                "Restrict observability endpoints to internal networks and require "
                "authentication. Centralize logging/monitoring and alert on anomalies.",
                "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                "logging/exposed-observability",
            ))

        # 2. Verbose error pages on 5xx
        try:
            resp = http.get(base.rstrip("/") + "/__asm_nonexistent_404__", timeout=6)
        except Exception:
            resp = None
        if resp is not None and resp.status_code >= 500:
            body = resp.text or ""
            if any(re.search(p, body, re.IGNORECASE) for p in VERBOSE_5XX_PATTERNS):
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A09-VERBOSE-ERROR-PAGE",
                    "LOW", "CWE-209",
                    f"Verbose server error page on {base}",
                    "The server returns a verbose 5xx page that may expose internals and "
                    "indicates unhandled exceptions are not being logged/tracked properly.",
                    "Return generic error pages, log full details server-side, and alert on "
                    "5xx anomalies.",
                    "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                    "logging/verbose-error",
                ))

    return findings
