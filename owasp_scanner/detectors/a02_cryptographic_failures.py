"""A02:2021 – Cryptographic Failures detector.

Detects:
- Missing / misconfigured HSTS
- Plaintext HTTP endpoints
- Secrets / keys leaked in body (API keys, private keys, JWTs, etc.)
- Weak TLS signals visible in headers (e.g. outdated SSL/TLS in headers)
"""

import re
import time

from .base import make_finding

CATEGORY = "A02:2021 – Cryptographic Failures"
RANK = 2

SECRET_PATTERNS = [
    ("aws_key", r"\bAKIA[0-9A-Z]{16}\b", "HIGH"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    ("jwt_token", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "HIGH"),
    ("stripe_key", r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b", "CRITICAL"),
    ("api_key", r"\b(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})", "HIGH"),
    ("google_api", r"\bAIza[0-9A-Za-z_\-]{35}\b", "HIGH"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "HIGH"),
    ("generic_password", r"\b(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"<>&;,]{6,})", "MEDIUM"),
    ("credit_card", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "CRITICAL"),
]

REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _redirect_evidence(http, base, timeout=6.0):
    """Capture the redirect observation for an http:// base URL.

    Returns a dict {"redirected": bool, "status_code": int|None, "location": str}
    so detectors can record precise evidence for suppressed findings.
    """
    if not base or not base.startswith("http://"):
        return {"redirected": False, "status_code": None, "location": ""}
    try:
        resp = http.get(base, timeout=timeout, follow_redirects=False)
        if resp.status_code in REDIRECT_STATUSES:
            location = (resp.headers.get("location") or "").strip()
            return {
                "redirected": True,
                "status_code": resp.status_code,
                "location": location,
            }
        return {"redirected": False, "status_code": resp.status_code, "location": ""}
    except Exception:
        return {"redirected": False, "status_code": None, "location": ""}


def detect_a02(domain, host, base_urls, http):
    findings = []
    seen = set()

    def add(finding):
        key = (finding["vulnerability_id"], finding["subdomain"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    # 1. Plaintext HTTP endpoint reachable
    #    Guard: an http:// URL that responds with a 3xx redirect to https:// does
    #    NOT serve application content over plaintext HTTP (e.g. 301 -> https://...),
    #    so it is not a plaintext-exposure finding.
    #
    #    Re-verification: sites behind load balancers can intermittently serve
    #    plaintext from one node while the rest redirect to HTTPS (observed on
    #    hackersinfotech.com). Probe up to 3 times and only report the finding if
    #    the endpoint NEVER redirects to HTTPS, so a one-off bad-node response
    #    does not produce a false positive.
    for base in list(base_urls)[:8]:
        if not base.startswith("http://"):
            continue
        probes = []
        for attempt in range(3):
            ev = _redirect_evidence(http, base)
            probes.append(ev)
            # Any attempt that proves a redirect to HTTPS disqualifies the finding.
            if ev["redirected"] and ev["location"].lower().startswith("https://"):
                break
            if attempt < 2:
                time.sleep(1.0)
        ev = probes[-1]
        if ev["redirected"] and ev["location"].lower().startswith("https://"):
            continue
        # If every probe failed to connect (no HTTP status observed), the host is
        # unreachable — that is NOT evidence of a plaintext exposure.
        if ev["status_code"] is None:
            continue
        add(make_finding(
            domain, host, CATEGORY, RANK, "A02-PLAINTEXT-HTTP",
            "HIGH", "CWE-319",
            f"Plaintext HTTP service reachable at {base}",
            f"The endpoint {base} is served over unencrypted HTTP. Passwords, tokens and "
            f"sensitive data can be eavesdropped or tampered with by network attackers.",
            "Redirect all HTTP traffic to HTTPS (301) and enable HSTS. Consider HTTPS-only "
            "configuration with certificate automation.",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "crypto/plaintext-http",
            confidence=0.95,
            status="confirmed",
            evidence=(
                f"HTTP {ev['status_code']} from {base} without redirecting to HTTPS on "
                f"all {len(probes)} probe(s)"
            ),
        ))
        break

    # 2. HSTS missing / weak on https endpoints
    for base in list(base_urls)[:8]:
        if not base.startswith("https://"):
            continue
        try:
            resp = http.get(base, timeout=8)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            continue
        hsts = hdrs.get("strict-transport-security", "")
        if not hsts:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A02-HSTS-MISSING",
                "MEDIUM", "CWE-523",
                f"HTTP Strict Transport Security (HSTS) header missing on {base}",
                "The server does not send the Strict-Transport-Security header. Without HSTS, "
                "browsers may connect over plaintext HTTP, enabling SSL stripping attacks.",
                "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all "
                "HTTPS responses and submit the domain for HSTS preloading.",
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "crypto/hsts-missing",
                confidence=0.9,
                status="confirmed",
                evidence=(f"GET {base} returned no Strict-Transport-Security header (HTTP {resp.status_code})"),
            ))
        elif "max-age=0" in hsts.lower():
            add(make_finding(
                domain, host, CATEGORY, RANK, "A02-HSTS-DISABLED",
                "HIGH", "CWE-523",
                f"HSTS explicitly disabled (max-age=0) on {base}",
                "The server sends Strict-Transport-Security with max-age=0, disabling the "
                "security policy.",
                "Remove max-age=0 and set a long max-age with includeSubDomains.",
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "crypto/hsts-disabled",
                confidence=0.95,
                status="confirmed",
                evidence=f"Observed header: Strict-Transport-Security: {hsts[:200]}",
            ))

    # 3. Secrets in page bodies
    for base in list(base_urls)[:5]:
        try:
            resp = http.get(base, timeout=8)
            body = resp.text or ""
        except Exception:
            continue
        if not body:
            continue
        for label, pattern, sev in SECRET_PATTERNS:
            if re.search(pattern, body):
                add(make_finding(
                    domain, host, CATEGORY, RANK, f"A02-SECRET-{label.upper()}",
                    sev, "CWE-312",
                    f"Potential {label.replace('_', ' ')} exposed in response body of {base}",
                    "The response body contains a string that matches a known secret/key format. "
                    "Exposed credentials can be harvested by anyone and used against the "
                    "organization.",
                    "Remove secrets from client-side content and version control. Rotate any "
                    "exposed keys immediately. Use a secrets manager and environment variables.",
                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                    f"crypto/exposed-{label}",
                ))
                break

    return findings
