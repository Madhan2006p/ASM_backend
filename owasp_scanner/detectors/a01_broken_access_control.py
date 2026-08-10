"""A01:2021 – Broken Access Control detector.

Detects:
- Admin / sensitive panels exposed without auth
- Insecure Direct Object Reference (IDOR) parameter patterns
- Sensitive files / directories reachable (forced browsing)
- Directory traversal path patterns
- Headers that bypass access control (X-Original-URL / X-Rewrite-URL)
"""

import re
from urllib.parse import urlparse

from .base import make_finding

CATEGORY = "A01:2021 – Broken Access Control"
RANK = 1

ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/manager", "/console",
    "/jenkins", "/actuator", "/phpmyadmin", "/login", "/dashboard",
]

# Indicators that a response is actually a login wall (i.e. access control IS enforced).
# Probes that redirect to or render one of these are NOT exposed admin panels.
LOGIN_REDIRECT_PATHS = ("login", "signin", "sign-in", "log-in", "auth")
LOGIN_PAGE_PATTERN = re.compile(
    r"<input[^>]+type=[\"']password[\"']"
    r"|name=[\"'](?:user_?name|username|loginfmt|email|passwd|password)[\"']"
    r"|\bsign\s?in\b|\blog\s?in\b|>login<|/login\b",
    re.IGNORECASE,
)

# SPA shell markers: a single-page app serves the same bootstrap HTML (empty
# root div + bundled JS/CSS) for EVERY route. A 200 on /admin that is only the
# shell does NOT prove an exposed admin panel — the real access control lives
# client-side (e.g. Keycloak / auth guard), and the JS bundle decides what to
# render. Without these markers it is treated as server-rendered content.
SPA_SHELL_PATTERN = re.compile(
    r"<div[^>]+id=[\"'](?:root|app|__next|__nuxt)[\"']"
    r"|<script[^>]+type=[\"']module[\"']"
    r"|<script[^>]+src=[\"'][^\"']*(?:assets|static|_next|dist)/[\"']",
    re.IGNORECASE,
)

# Client-side auth-guard markers inside the served HTML/bundle. A shell alone
# does not prove access control is enforced client-side — these markers do
# (Keycloak/OAuth token handling, login routes). Absent them, the SPA may
# render admin content for anonymous users, so the finding stays "potential".
AUTH_GUARD_PATTERN = re.compile(
    r"keycloak|kc_access_token|kc_refresh_token|oidc|oauth"
    r"|bearer[^\"']{0,40}token|isauthenticated|authguard|requireauth"
    r"|\.login\b|/login\b|sign\s?in",
    re.IGNORECASE,
)

# Paths that typically should NOT be publicly reachable
SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.aws/credentials",
    "/config.php.bak", "/backup.zip", "/db.sql", "/dump.sql",
    "/.htaccess", "/web.config", "/phpinfo.php", "/info.php",
]

IDOR_PARAM_PATTERN = re.compile(
    r"\b(id|user_?id|account_?id|file_?id|doc_?id|order_?id|invoice_?id|"
    r"record_?id|profile_?id|customer_?id|uid|pid|oid|item_?id|product_?id|"
    r"report_?id|num|number|ref|uuid|guid)\b",
    re.IGNORECASE,
)

TRAVERSAL_PATTERNS = [
    "..%2f", "..%2F", "../", "..\\", "%2e%2e%2f", "%2e%2e%5c",
    "....//", "..;/", "..%00",
]

ACCESS_BYPASS_HEADERS = ["x-original-url", "x-rewrite-url", "x-custom-ip-authorization"]


def detect_a01(domain, host, base_urls, http):
    findings = []
    seen = set()

    def add(finding):
        key = (finding["vulnerability_id"], finding["subdomain"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    # 1. Probe admin + sensitive paths for 200/302/403-with-content indicators.
    # Probed in parallel (per host) so slow/unresponsive hosts don't stall the scan.
    import concurrent.futures
    probe_targets = [base.rstrip("/") + p for base in list(base_urls)[:4] for p in ADMIN_PATHS + SENSITIVE_PATHS]

    def _probe(url):
        from .base import HTTPClient
        try:
            # follow_redirects is already the default; track the FINAL url so
            # admin paths that bounce to a login page are not misreported.
            with HTTPClient() as probe_http:
                r = probe_http.get(url, timeout=4)
            final_path = (urlparse(str(r.url)).path or "").lower()
            # Keep a generous slice so login forms on long pre-login pages are seen.
            return url, r.status_code, (r.text or "")[:8000].lower(), final_path
        except Exception:
            return url, None, "", ""

    for url, code, body, final_path in concurrent.futures.ThreadPoolExecutor(max_workers=8).map(_probe, probe_targets):
        if code not in (200, 201):
            continue
        path = urlparse(url).path
        is_adminish = path in ADMIN_PATHS or any(a in path for a in ("admin", "console", "jenkins", "actuator", "phpmyadmin", "manager", "login", "dashboard"))
        # False positives: default 404 pages returning 200
        if any(m in body for m in ("not found", "404", "page not found", "does not exist")):
            continue
        # False positives: paths that redirect to (or render) a login page are
        # behind a login wall — access control is enforced, nothing is exposed.
        if any(p in final_path for p in LOGIN_REDIRECT_PATHS) or LOGIN_PAGE_PATTERN.search(body):
            continue
        if is_adminish:
            # False positive: a 200 that is only the SPA bootstrap shell (root div +
            # bundled JS) means the app is client-side rendered and the server serves
            # index.html for every route — it does NOT expose an admin panel.
            # E.g. /bms/admin -> 200 SPA shell while the Keycloak auth guard
            # redirects unauthenticated users to the login page.
            if SPA_SHELL_PATTERN.search(body):
                # confirmed only when the served shell references a client-side
                # auth guard (Keycloak / token / login route); otherwise the SPA
                # may render for anonymous users -> keep it potential.
                auth_guard = AUTH_GUARD_PATTERN.search(body)
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A01-ADMIN-ROUTE-NO-SERVER-GUARD",
                    "LOW", "CWE-284",
                    f"Admin route {url} returns SPA shell without server-side auth guard",
                    f"The URL {url} returned HTTP {code} serving the single-page-app shell "
                    f"(index.html for every route). No server-side access control is enforced "
                    f"on this path — whether admin functionality renders is decided entirely "
                    f"client-side (e.g. Keycloak/auth guard). This is NOT a directly exposed "
                    f"admin panel, but the web server should enforce authentication before "
                    f"serving the application shell.",
                    "Enforce authentication at the reverse proxy / web server level for admin "
                    "routes instead of relying solely on client-side guards, which are trivially "
                    "bypassable (e.g. by calling backend APIs directly).",
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    "access-control/admin-route-no-server-guard",
                    confidence=(0.85 if auth_guard else 0.6),
                    status=("confirmed" if auth_guard else "potential"),
                    evidence=(
                        f"GET {url} -> HTTP {code}; response is SPA shell (root div + module script) at {final_path or path}; "
                        f"client-side auth guard {'detected' if auth_guard else 'NOT verified'}"
                    ),
                ))
                continue
            add(make_finding(
                domain, host, CATEGORY, RANK, "A01-ADMIN-PANEL-EXPOSED",
                "HIGH", "CWE-284",
                f"Potentially exposed admin/management panel at {url}",
                f"The URL {url} returned HTTP {code} with server-rendered content without "
                f"evidence of authentication. Admin panels and management consoles should "
                f"never be publicly reachable.",
                "Restrict access to administrative interfaces using IP allow-lists, network "
                "segmentation and strong multi-factor authentication. Remove public exposure "
                "of management paths.",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                "access-control/admin-panel-exposed",
                confidence=0.7,
                status="potential",
                evidence=f"GET {url} -> HTTP {code}; final page path: {final_path or path}",
            ))
        else:
            if any(m in body for m in ("<?php", "mysql", "password=", "db_password")):
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A01-SENSITIVE-FILE-EXPOSED",
                    "CRITICAL", "CWE-200",
                    f"Sensitive file exposed: {url}",
                    f"The sensitive path {url} returned HTTP {code} and its content suggests a "
                    f"real file (config, backup or database artifact) rather than a 404 page.",
                    "Remove sensitive files from the web root immediately, block the path in the "
                    "web server config, and rotate any credentials found.",
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    "access-control/sensitive-file-exposed",
                    confidence=0.85,
                    status="potential",
                    evidence=f"GET {url} -> HTTP {code}; body contains sensitive markers ({[m for m in ("<?php", "mysql", "password=", "db_password") if m in body]})",
                ))

    # 2. IDOR indicators on query parameters
    for base in list(base_urls)[:6]:
        parsed = urlparse(base)
        query = parsed.query or ""
        if query and IDOR_PARAM_PATTERN.search(query):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A01-IDOR-PARAMETER",
                "MEDIUM", "CWE-639",
                f"Potential Insecure Direct Object Reference parameter in {parsed.path or '/'}",
                f"The endpoint exposes object-referencing parameters ({query}) in the URL. "
                f"Without server-side authorization checks, users could access or modify other "
                f"users' objects by tampering with these values.",
                "Enforce server-side authorization on every object reference. Never trust "
                "client-supplied identifiers — use session-derived IDs or signed references.",
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html",
                "access-control/idor-parameter",
            ))

    # 3. Path traversal strings present in URL
    for base in list(base_urls)[:6]:
        for pattern in TRAVERSAL_PATTERNS:
            if pattern in base:
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A01-PATH-TRAVERSAL",
                    "HIGH", "CWE-22",
                    f"Path traversal pattern detected in URL: {base[:120]}",
                    f"The URL contains traversal sequences ({pattern}) which, if echoed into "
                    f"filesystem paths, could allow reading arbitrary files on the server.",
                    "Validate and sanitize all file path inputs. Use an allow-list of permitted "
                    "files and reject any input containing traversal sequences.",
                    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.html",
                    "access-control/path-traversal",
                ))
                break

    # 4. Access-control bypass headers in response
    resp_headers = {}
    try:
        first = http.get(list(base_urls)[0], timeout=6)
        resp_headers = {k.lower(): v for k, v in first.headers.items()}
    except Exception:
        pass
    for hdr in ACCESS_BYPASS_HEADERS:
        if hdr in resp_headers:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A01-ACCESS-BYPASS-HEADER",
                "HIGH", "CWE-284",
                f"Access-control bypass header echoed by server: {hdr}",
                f"The server returned the header '{hdr}'. Such headers can be abused to bypass "
                f"URL-based access control (e.g. reaching /admin via /; X-Original-URL).",
                "Validate that the reverse proxy strips client-supplied X-Original-URL / "
                "X-Rewrite-URL headers and enforces authorization on the backend.",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                "access-control/bypass-header",
            ))

    return findings
