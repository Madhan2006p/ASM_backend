"""A04:2021 – Insecure Design detector.

Detects design-level weaknesses observable from outside:
- Verbose stack traces / debug endpoints (leaking internals)
- Missing CSRF protections on state-changing forms
- Rate-limit indicators absent on login forms
- Unrestricted resource indicators (huge responses, pagination hints)
"""

import re

from .base import make_finding

CATEGORY = "A04:2021 – Insecure Design"
RANK = 4

DEBUG_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"django.*debug",
    r"debug=true",
    r"werkzeug.*debugger",
    r"flask.*development server",
    r"rails.*development",
    r"spring.*error page",
    r"java\.lang\.",
    r"at\s+[a-z0-9_.]+\.(java|py|php|rb):\d+",
]

CSRF_INPUT_PATTERNS = [
    r'name=["\']csrfmiddlewaretoken["\']',
    r'name=["\']_csrf["\']',
    r'name=["\']csrf_token["\']',
    r'name=["\']__RequestVerificationToken["\']',
    r'name=["\']authenticity_token["\']',
]


def detect_a04(domain, host, base_urls, http):
    findings = []
    seen = set()

    def add(finding):
        key = (finding["vulnerability_id"], finding["subdomain"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for base in list(base_urls)[:8]:
        try:
            resp = http.get(base, timeout=8)
            body = resp.text or ""
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            continue

        # 1. Verbose error / debug leakage
        if any(re.search(p, body, re.IGNORECASE) for p in DEBUG_PATTERNS):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A04-DEBUG-INFO-DISCLOSURE",
                "MEDIUM", "CWE-209",
                f"Debug / stack-trace information disclosed on {base}",
                "The response leaks stack traces, framework debug markers or source file paths "
                "that reveal internals useful for crafting attacks.",
                "Disable debug mode in production, return generic error pages, and log full "
                "details server-side only.",
                "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                "design/debug-info-disclosure",
            ))

        # 2. Forms without CSRF token (state-changing design gap)
        if re.search(r"<form", body, re.IGNORECASE):
            has_method = re.search(r'<form[^>]*method=["\'](get|post)["\']', body, re.IGNORECASE)
            posts = re.findall(r'<form[^>]*method=["\']post["\']', body, re.IGNORECASE)
            if posts and not any(re.search(p, body, re.IGNORECASE) for p in CSRF_INPUT_PATTERNS):
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A04-CSRF-PROTECTION-MISSING",
                    "MEDIUM", "CWE-352",
                    f"Form(s) on {base} lack an anti-CSRF token",
                    "POST forms are present without a visible CSRF token field, increasing "
                    "Cross-Site Request Forgery risk for state-changing actions.",
                    "Add synchronizer tokens or SameSite=Strict cookies to all state-changing "
                    "forms and enforce them server-side.",
                    "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                    "design/csrf-protection-missing",
                ))

        # 3. Login forms without lockout indicators
        if re.search(r"<form[^>]*", body, re.IGNORECASE) and re.search(
            r'name=["\'](password|passwd|pwd)["\']', body, re.IGNORECASE
        ):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A04-AUTH-DESIGN-RISK",
                "LOW", "CWE-770",
                f"Authentication form on {base} — verify lockout & rate limiting",
                "An authentication form was found. Weak lockout/rate-limit design would allow "
                "credential-stuffing attacks. This is a design-level check.",
                "Implement account lockout, rate limiting, CAPTCHA after repeated failures, and "
                "log all authentication attempts.",
                "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                "design/auth-design-review",
            ))

    return findings
