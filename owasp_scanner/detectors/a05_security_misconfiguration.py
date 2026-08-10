"""A05:2021 – Security Misconfiguration detector.

Detects:
- Missing / weak security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- CORS wildcard with credentials
- Directory listing enabled
- Dangerous HTTP methods
- Server / technology fingerprint disclosure
- Missing cookie security flags
"""

import re

from .base import make_finding, header_map

CATEGORY = "A05:2021 – Security Misconfiguration"
RANK = 5

# Header → (vulnerability_id, template_id, CWE, severity).
# vulnerability_id/template_id deliberately match attacksurface/scanner/vulnerability_scanner.py
# so OWASP findings and Python-scanner findings deduplicate against each other.
SECURITY_HEADERS = {
    "content-security-policy": ("CSP-MISSING", "headers/csp-missing", "CWE-693", "HIGH"),
    "x-frame-options": ("XFO-MISSING", "headers/x-frame-options-missing", "CWE-1021", "MEDIUM"),
    "x-content-type-options": ("XCTO-MISSING", "headers/x-content-type-options-missing", "CWE-693", "LOW"),
    "strict-transport-security": ("HSTS-MISSING", "headers/hsts-missing", "CWE-523", "MEDIUM"),
    "referrer-policy": ("REFERRERPOLICY-MISSING", "headers/referrer-policy-missing", "CWE-200", "LOW"),
    "permissions-policy": ("PERMISSIONSPOLICY-MISSING", "headers/permissions-policy-missing", "CWE-693", "LOW"),
    "x-xss-protection": ("XSSPROTECT-MISSING", "headers/x-xss-protection-missing", "CWE-933", "LOW"),
}

DIR_LISTING_PATTERNS = ["index of /", "directory listing", "<title>index of"]


def detect_a05(domain, host, base_urls, http):
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
            hdrs = header_map(resp)
            body = (resp.text or "").lower()
        except Exception:
            continue

        # 1. Missing security headers (each reported individually)
        for header, (vuln_id, tpl_id, cwe, sev) in SECURITY_HEADERS.items():
            if header not in hdrs:
                add(make_finding(
                    domain, host, CATEGORY, RANK, vuln_id,
                    sev, cwe,
                    f"Missing {header} security header on {base}",
                    f"The response from {base} does not include the {header} header, weakening "
                    f"browser-side defenses against common web attacks.",
                    f"Emit '{header}' with a restrictive policy on all responses (see OWASP "
                    f"Secure Headers Project).",
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                    tpl_id,
                ))

        # 2. CORS wildcard with credentials
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            add(make_finding(
                domain, host, CATEGORY, RANK, "A05-CORS-WILDCARD-CREDENTIALS",
                "HIGH", "CWE-942",
                f"CORS wildcard with credentials on {base}",
                "Access-Control-Allow-Origin: * combined with Allow-Credentials allows any "
                "origin to read authenticated responses.",
                "Never combine wildcard origins with credentials. Reflect and allow-list exact "
                "trusted origins.",
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Cross_Origin_Resource_Sharing.html",
                "misconfig/cors-wildcard-credentials",
            ))

        # 3. Directory listing
        if resp.status_code == 200 and any(p in body for p in DIR_LISTING_PATTERNS):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A05-DIRECTORY-LISTING",
                "MEDIUM", "CWE-548",
                f"Directory listing enabled on {base}",
                "The server returns an auto-generated index of directory contents, exposing "
                "file names and structure to anyone.",
                "Disable directory indexing in the web server configuration.",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                "misconfig/directory-listing",
            ))

        # 4. Dangerous HTTP methods
        allow = hdrs.get("allow", "") or hdrs.get("access-control-allow-methods", "")
        if any(m in allow.upper() for m in ["PUT", "DELETE", "TRACE"]):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A05-DANGEROUS-METHODS",
                "MEDIUM", "CWE-749",
                f"Dangerous HTTP methods advertised on {base}: {allow}",
                "The server advertises PUT/DELETE/TRACE which can allow unauthorized file "
                "manipulation or cross-site tracing.",
                "Disable unused HTTP methods and reject TRACE at the web server layer.",
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.html",
                "misconfig/dangerous-methods",
            ))

        # 5. Server fingerprint disclosure
        server = hdrs.get("server", "")
        xpb = hdrs.get("x-powered-by", "")
        if server:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A05-SERVER-FINGERPRINT",
                "LOW", "CWE-200",
                f"Server fingerprint disclosed on {base}: {server}",
                "The Server header reveals the exact web server software and may reveal "
                "version details.",
                "Suppress/obscure the Server header (ServerTokens Prod, server_tokens off).",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                "misconfig/server-fingerprint",
            ))
        if xpb:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A05-POWEREDBY-DISCLOSURE",
                "LOW", "CWE-200",
                f"Technology disclosure on {base}: X-Powered-By: {xpb}",
                "The X-Powered-By header reveals the application framework/technology.",
                "Remove the X-Powered-By header in framework or proxy configuration.",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                "misconfig/x-powered-by",
            ))

        # 6. Cookie security flags
        set_cookie = hdrs.get("set-cookie", "")
        if set_cookie:
            cookie_name = set_cookie.split("=")[0] if "=" in set_cookie else "session"
            if "secure" not in set_cookie.lower():
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A05-COOKIE-NOSECURE",
                    "MEDIUM", "CWE-614",
                    f"Cookie '{cookie_name}' missing Secure flag on {base}",
                    "Cookies are sent without the Secure attribute and may be transmitted over "
                    "plaintext HTTP.",
                    "Set the Secure attribute on all cookies.",
                    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html",
                    "misconfig/cookie-no-secure",
                ))
            if "httponly" not in set_cookie.lower():
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A05-COOKIE-NOHTTPONLY",
                    "MEDIUM", "CWE-1004",
                    f"Cookie '{cookie_name}' missing HttpOnly flag on {base}",
                    "Cookies are readable by client-side scripts, increasing XSS session "
                    "hijacking risk.",
                    "Set the HttpOnly attribute on session cookies.",
                    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html",
                    "misconfig/cookie-no-httponly",
                ))

    return findings
