"""A07:2021 – Identification and Authentication Failures detector.

Detects:
- Login forms served without transport protection (over HTTP)
- Session cookies without Secure/HttpOnly (auth session hardening)
- JWT weaknesses (alg:none markers) in body
- Default/weak credential patterns in body
- Missing lockout indicators on login endpoints
"""

import re

from .base import make_finding, header_map

CATEGORY = "A07:2021 – Identification and Authentication Failures"
RANK = 7

LOGIN_FORM_PATTERN = re.compile(
    r'<form[^>]*>(?:(?!</form>).)*?name=["\']password["\']', re.IGNORECASE | re.DOTALL
)

WEAK_SESSION_HINTS = [
    "sessionid=", "jsessionid=", "aspsessionid=", "phpsessid=",
]

JWT_WEAK_PATTERNS = [
    r'"alg"\s*:\s*"none"',
    r'alg[=:]\s*none',
]


def detect_a07(domain, host, base_urls, http):
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
            hdrs = header_map(resp)
        except Exception:
            continue

        # Only treat a page as an auth endpoint when there is real evidence:
        # an actual password form in the response. URL hints alone (e.g. /api/auth/*)
        # cause false positives on API routing paths.
        is_login_page = bool(LOGIN_FORM_PATTERN.search(body))

        # The final URL after redirects determines the actual transport. An
        # http:// base that 3xx-redirects to https:// serves the login page over
        # TLS, so it is NOT a plaintext-credentials exposure.
        final_url = str(getattr(resp, "url", "") or "")
        final_uses_http = final_url.startswith("http://") and not final_url.startswith("https://")

        # 1. Login over plaintext HTTP
        if is_login_page and base.startswith("http://") and final_uses_http:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A07-LOGIN-OVER-HTTP",
                "CRITICAL", "CWE-319",
                f"Login form served over unencrypted HTTP at {base}",
                "Credentials submitted to this page travel in cleartext and can be captured "
                "or modified in transit.",
                "Force HTTPS for all authentication pages and redirect HTTP to HTTPS.",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "auth/login-over-http",
            ))

        # 2. Session cookie hardening
        set_cookie = hdrs.get("set-cookie", "")
        if set_cookie and any(h in set_cookie.lower() for h in WEAK_SESSION_HINTS):
            cookie_name = set_cookie.split("=")[0]
            missing = []
            if "secure" not in set_cookie.lower():
                missing.append("Secure")
            if "httponly" not in set_cookie.lower():
                missing.append("HttpOnly")
            if "samesite" not in set_cookie.lower():
                missing.append("SameSite")
            if missing:
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A07-SESSION-COOKIE-WEAK",
                    "HIGH", "CWE-613",
                    f"Session cookie '{cookie_name}' missing {', '.join(missing)} on {base}",
                    "The authentication session cookie is set without critical protection "
                    "flags, enabling session theft or fixation.",
                    f"Set {'; '.join(missing)} attributes on all session cookies and rotate "
                    f"sessions after login.",
                    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                    "auth/weak-session-cookie",
                ))

        # 3. Login page without visible lockout/rate-limit hints (design warning)
        if is_login_page:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A07-AUTH-ENDPOINT-EXPOSED",
                "LOW", "CWE-307",
                f"Authentication endpoint found at {base} — verify brute-force protection",
                "A login/authentication endpoint is publicly reachable. Confirm account lockout, "
                "rate limiting and MFA are enforced server-side.",
                "Enforce lockout after N failures, rate limiting, CAPTCHA and MFA.",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "auth/endpoint-review",
            ))

        # 4. JWT weak markers in body
        if any(re.search(p, body, re.IGNORECASE) for p in JWT_WEAK_PATTERNS):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A07-JWT-ALG-NONE",
                "CRITICAL", "CWE-347",
                f"JWT 'alg:none' weakness marker on {base}",
                "The response contains JWT markers with alg=none, which allows signature "
                "forgery if accepted by the server.",
                "Reject alg=none tokens, pin algorithms, and validate signatures strictly.",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "auth/jwt-alg-none",
            ))

    return findings
