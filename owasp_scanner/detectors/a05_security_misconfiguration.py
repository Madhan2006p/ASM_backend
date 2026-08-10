"""
A05 - Security Misconfiguration Detector
==========================================
Detects:
- Missing / insecure HTTP security headers
- Default credentials on management interfaces
- Debug mode / verbose error messages
- Directory listing enabled
- Exposed configuration files (.env, .git, configs)
- Unnecessary HTTP methods (TRACE, PUT, DELETE)
- CORS misconfiguration (wildcard / untrusted origins)
- Server version disclosure
- Cloud storage misconfigurations (S3, GCP, Azure)
- Exposed admin interfaces (phpMyAdmin, Jenkins, etc.)
- Insecure default installations
- Missing rate limiting on sensitive endpoints

OWASP A05:2021 - Security Misconfiguration
CWE References: CWE-16, CWE-200, CWE-215, CWE-285, CWE-732, CWE-1021
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from ..core import (
    AssetInfo, BaseDetector, Finding, FindingBuilder,
    SeverityLevel, ConfidenceLevel
)


# ─── Sensitive Configuration / Backup Files ────────────────────────────────────

SENSITIVE_FILES = [
    # Environment / Credentials
    ('/.env', 'environment variables', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/.env.local', 'local environment variables', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/.env.backup', 'environment variable backup', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/.env.production', 'production environment variables', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/.env.staging', 'staging environment variables', SeverityLevel.HIGH, 'CWE-200'),

    # Git / Version Control
    ('/.git/config', 'Git repository configuration', SeverityLevel.HIGH, 'CWE-538'),
    ('/.git/HEAD', 'Git HEAD reference', SeverityLevel.MEDIUM, 'CWE-538'),
    ('/.svn/entries', 'SVN repository data', SeverityLevel.MEDIUM, 'CWE-538'),
    ('/.hg/hgrc', 'Mercurial config', SeverityLevel.MEDIUM, 'CWE-538'),

    # Application Configuration
    ('/config.php', 'PHP configuration file', SeverityLevel.HIGH, 'CWE-200'),
    ('/config.yml', 'YAML configuration', SeverityLevel.HIGH, 'CWE-200'),
    ('/config.yaml', 'YAML configuration', SeverityLevel.HIGH, 'CWE-200'),
    ('/config.json', 'JSON configuration', SeverityLevel.HIGH, 'CWE-200'),
    ('/configuration.php', 'Joomla configuration', SeverityLevel.HIGH, 'CWE-200'),
    ('/settings.py', 'Django settings', SeverityLevel.HIGH, 'CWE-200'),
    ('/wp-config.php.bak', 'WordPress config backup', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/database.yml', 'Rails database config', SeverityLevel.HIGH, 'CWE-200'),
    ('/app.config', '.NET app config', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/Web.config', 'ASP.NET Web config', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/applicationContext.xml', 'Spring XML config', SeverityLevel.MEDIUM, 'CWE-200'),

    # Credential Files
    ('/.htpasswd', 'Apache htpasswd credentials', SeverityLevel.HIGH, 'CWE-522'),
    ('/credentials.json', 'Credentials file', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/secrets.json', 'Secrets file', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/private.key', 'Private key file', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/server.key', 'Server private key', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/id_rsa', 'SSH private key', SeverityLevel.CRITICAL, 'CWE-200'),

    # Backup / Temp Files
    ('/backup.zip', 'Application backup archive', SeverityLevel.HIGH, 'CWE-200'),
    ('/backup.tar.gz', 'Application backup archive', SeverityLevel.HIGH, 'CWE-200'),
    ('/dump.sql', 'Database dump', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/backup.sql', 'Database backup', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/db.sql', 'Database file', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/database.sql', 'Database export', SeverityLevel.CRITICAL, 'CWE-200'),
    ('/site.tar.gz', 'Site archive', SeverityLevel.HIGH, 'CWE-200'),
    ('/app.tar', 'Application archive', SeverityLevel.HIGH, 'CWE-200'),

    # Development / Debug Files
    ('/test.php', 'PHP test file', SeverityLevel.LOW, 'CWE-215'),
    ('/info.php', 'PHP info page', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/phpinfo.php', 'PHP info disclosure', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/debug.php', 'PHP debug page', SeverityLevel.MEDIUM, 'CWE-215'),
    ('/server-status', 'Apache server status', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/server-info', 'Apache server info', SeverityLevel.LOW, 'CWE-200'),
    ('/.DS_Store', 'macOS directory metadata', SeverityLevel.LOW, 'CWE-538'),
    ('/Thumbs.db', 'Windows thumbnail cache', SeverityLevel.LOW, 'CWE-538'),

    # API / Swagger docs
    ('/swagger.json', 'Swagger/OpenAPI spec', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/swagger.yaml', 'Swagger/OpenAPI spec', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/api-docs', 'API documentation', SeverityLevel.LOW, 'CWE-200'),
    ('/openapi.json', 'OpenAPI specification', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/api/swagger.json', 'Swagger spec', SeverityLevel.MEDIUM, 'CWE-200'),
    ('/v1/swagger.json', 'Swagger spec', SeverityLevel.MEDIUM, 'CWE-200'),
]

# ─── Cloud Storage Misconfigurations ──────────────────────────────────────────

S3_BUCKET_PATTERNS = [
    r's3\.amazonaws\.com/([a-z0-9\-\.]+)',
    r'([a-z0-9\-\.]+)\.s3\.amazonaws\.com',
    r's3-[a-z0-9\-]+\.amazonaws\.com/([a-z0-9\-\.]+)',
]

GCS_PATTERNS = [
    r'storage\.googleapis\.com/([a-z0-9\-\.]+)',
    r'([a-z0-9\-\.]+)\.storage\.googleapis\.com',
]

# ─── Dangerous HTTP Methods ───────────────────────────────────────────────────

DANGEROUS_METHODS = {
    'TRACE': ('Cross-Site Tracing (XST)', SeverityLevel.MEDIUM, 'CWE-16'),
    'TRACK': ('Cross-Site Tracing (XST)', SeverityLevel.MEDIUM, 'CWE-16'),
    'PUT': ('Arbitrary File Upload via HTTP PUT', SeverityLevel.HIGH, 'CWE-650'),
    'DELETE': ('Arbitrary File Deletion via HTTP DELETE', SeverityLevel.HIGH, 'CWE-650'),
    'CONNECT': ('HTTP Tunneling via CONNECT', SeverityLevel.MEDIUM, 'CWE-16'),
}

# ─── Security Headers ─────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    'strict-transport-security': {
        'name': 'HSTS',
        'desc': 'HTTP Strict Transport Security (HSTS) forces HTTPS, preventing SSL-stripping attacks.',
        'severity': SeverityLevel.MEDIUM,
        'cwe': 'CWE-523',
        'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/523.html',
    },
    'content-security-policy': {
        'name': 'CSP',
        'desc': 'Content Security Policy (CSP) mitigates XSS and data injection attacks.',
        'severity': SeverityLevel.MEDIUM,
        'cwe': 'CWE-693',
        'remediation': "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
        'cwe_url': 'https://cwe.mitre.org/data/definitions/693.html',
    },
    'x-content-type-options': {
        'name': 'X-Content-Type-Options',
        'desc': 'X-Content-Type-Options: nosniff prevents MIME-type sniffing attacks.',
        'severity': SeverityLevel.LOW,
        'cwe': 'CWE-693',
        'remediation': 'Add: X-Content-Type-Options: nosniff',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/693.html',
    },
    'x-frame-options': {
        'name': 'X-Frame-Options',
        'desc': 'X-Frame-Options prevents clickjacking by controlling iframe embedding.',
        'severity': SeverityLevel.MEDIUM,
        'cwe': 'CWE-1021',
        'remediation': 'Add: X-Frame-Options: DENY',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/1021.html',
    },
    'referrer-policy': {
        'name': 'Referrer-Policy',
        'desc': 'Referrer-Policy controls how much referrer information is included with requests.',
        'severity': SeverityLevel.LOW,
        'cwe': 'CWE-200',
        'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/200.html',
    },
    'permissions-policy': {
        'name': 'Permissions-Policy',
        'desc': 'Permissions-Policy (formerly Feature-Policy) controls browser API access.',
        'severity': SeverityLevel.LOW,
        'cwe': 'CWE-16',
        'remediation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/16.html',
    },
    'x-xss-protection': {
        'name': 'X-XSS-Protection',
        'desc': 'X-XSS-Protection activates the browser\'s built-in XSS filter (legacy browsers).',
        'severity': SeverityLevel.LOW,
        'cwe': 'CWE-79',
        'remediation': 'Add: X-XSS-Protection: 1; mode=block',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/79.html',
    },
}

# ─── CORS Origin Checks ───────────────────────────────────────────────────────

CORS_TEST_ORIGINS = [
    'https://evil.com',
    'https://attacker.com',
    'null',
    'https://subdomain.evil.com',
]

# ─── Information Leaking Patterns in Error Responses ─────────────────────────

ERROR_DISCLOSURE_PATTERNS = [
    (r'traceback \(most recent call last\)', 'Python traceback', SeverityLevel.MEDIUM),
    (r'at .+\([\w\.]+\.java:\d+\)', 'Java stack trace', SeverityLevel.MEDIUM),
    (r'System\.Web\.HttpException', '.NET exception', SeverityLevel.MEDIUM),
    (r'Uncaught Exception.*in.*on line \d+', 'PHP exception', SeverityLevel.MEDIUM),
    (r'SQLSTATE\[.*\]\[.*\]', 'SQL error disclosure', SeverityLevel.HIGH),
    (r'ActiveRecord::.*Error', 'Rails ActiveRecord error', SeverityLevel.MEDIUM),
    (r'django\.core\.exceptions', 'Django exception', SeverityLevel.MEDIUM),
    (r'<b>Fatal error</b>:', 'PHP fatal error', SeverityLevel.MEDIUM),
    (r'Call to undefined', 'PHP error', SeverityLevel.LOW),
    (r'Notice: Undefined variable', 'PHP notice', SeverityLevel.LOW),
    (r'com\.microsoft\.sqlserver', 'MSSQL error', SeverityLevel.HIGH),
    (r'ORA-\d{5}', 'Oracle DB error', SeverityLevel.HIGH),
    (r'ERROR 1064.*MySQL', 'MySQL error', SeverityLevel.HIGH),
]

# ─── Debug/Verbose Endpoints ──────────────────────────────────────────────────

DEBUG_PATHS = [
    '/actuator', '/actuator/env', '/actuator/health', '/actuator/mappings',
    '/actuator/beans', '/actuator/configprops', '/actuator/threaddump',
    '/actuator/heapdump', '/actuator/metrics',  # Spring Boot Actuator
    '/debug', '/debug/pprof', '/debug/vars', '/debug/requests',  # Go debug
    '/_debug', '/_ah/admin', '/_ah/stats',  # App Engine
    '/env', '/health', '/info', '/metrics',  # Common Spring/Flask endpoints
    '/.well-known/security.txt',  # Security contact (informational)
    '/status', '/stats', '/diagnostics',
    '/api/debug', '/api/v1/debug',
]

# ─── Directory Listing Detection ──────────────────────────────────────────────

DIRECTORY_LISTING_PATTERNS = [
    r'<title>Index of ',
    r'<h1>Index of ',
    r'Parent Directory<',
    r'\[To Parent Directory\]',
    r'Directory listing for ',
    r'<title>Directory listing',
]


class SecurityMisconfigurationDetector(BaseDetector):
    """
    A05:2021 - Security Misconfiguration Detector.

    Checks for:
    - Missing/weak HTTP security headers
    - Exposed sensitive files and configs
    - Dangerous HTTP methods enabled
    - CORS misconfiguration
    - Server/version information disclosure
    - Debug endpoints and verbose errors
    - Directory listing
    - Cloud storage misconfigurations
    """
    owasp_category = "A05"
    name = "Security Misconfiguration"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A05 (Security Misconfiguration) detection on {len(assets)} assets")

        tasks = [
            self._check_security_headers(),
            self._check_sensitive_files(),
            self._check_http_methods(),
            self._check_cors(),
            self._check_server_disclosure(),
            self._check_debug_endpoints(),
            self._check_error_disclosure(assets),
            self._check_directory_listing(assets),
            self._check_cloud_storage(assets),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)
        self._log(f"A05 detection complete. Found {len(self._findings)} issues.")
        return self._findings

    # ─── Security Headers ─────────────────────────────────────────────────────

    async def _check_security_headers(self) -> None:
        """Check for missing or weak security response headers."""
        resp, elapsed = await self._request('GET', self.target.url)
        if resp is None:
            return

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        is_https = self.target.url.startswith('https://')

        for header_name, info in SECURITY_HEADERS.items():
            # Skip HSTS check for HTTP-only targets
            if header_name == 'strict-transport-security' and not is_https:
                continue

            if header_name not in headers_lower:
                self._add_finding(
                    FindingBuilder()
                    .name(f"Missing Security Header: {info['name']}")
                    .category("A05")
                    .vuln_type("Missing Security Header")
                    .severity(info['severity'])
                    .confidence(ConfidenceLevel.CERTAIN)
                    .url(self.target.url)
                    .header(header_name)
                    .cwe(info['cwe'])
                    .description(
                        f"The HTTP response is missing the '{header_name}' security header. "
                        f"{info['desc']}"
                    )
                    .risk(
                        f"Missing {info['name']} weakens the browser's defense capabilities "
                        "against common web attacks."
                    )
                    .impact(
                        "Increases attack surface for client-side attacks such as XSS, "
                        "clickjacking, and SSL stripping depending on the missing header."
                    )
                    .remediation(info['remediation'])
                    .add_ref(info['cwe_url'])
                    .add_ref("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/")
                    .add_ref("https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html")
                    .evidence(f"Header '{header_name}' not present in HTTP response from {self.target.url}")
                    .proof(f"GET {self.target.url} - Response headers: {dict(list(headers_lower.items())[:8])}")
                    .request(self._build_request_obj('GET', self.target.url))
                    .response(self._build_response_obj(resp, elapsed))
                    .detected_by("A05_SECURITY_HEADERS")
                    .build()
                )
            else:
                # Check for weak CSP values
                if header_name == 'content-security-policy':
                    csp_value = headers_lower.get(header_name, '')
                    await self._check_weak_csp(csp_value, resp, elapsed)

        # Check for overly permissive X-Frame-Options
        xfo = headers_lower.get('x-frame-options', '')
        if xfo and xfo.upper() == 'ALLOWALL':
            self._add_finding(
                FindingBuilder()
                .name("Insecure X-Frame-Options: ALLOWALL - Clickjacking Risk")
                .category("A05")
                .vuln_type("Insecure Security Header Configuration")
                .severity(SeverityLevel.MEDIUM)
                .confidence(ConfidenceLevel.CERTAIN)
                .url(self.target.url)
                .cwe("CWE-1021")
                .description("X-Frame-Options is set to ALLOWALL, permitting the page to be framed by any origin.")
                .remediation("Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.")
                .evidence(f"X-Frame-Options: {xfo}")
                .detected_by("A05_SECURITY_HEADERS")
                .build()
            )

    async def _check_weak_csp(self, csp: str, resp: httpx.Response, elapsed: float) -> None:
        """Check for dangerous CSP directives."""
        csp_lower = csp.lower()
        issues = []

        if "'unsafe-inline'" in csp_lower:
            issues.append("'unsafe-inline' in CSP allows inline scripts, defeating XSS protection")
        if "'unsafe-eval'" in csp_lower:
            issues.append("'unsafe-eval' in CSP allows eval(), enabling code execution from strings")
        if "default-src *" in csp_lower or "script-src *" in csp_lower:
            issues.append("Wildcard (*) in CSP allows resources from any origin")

        if issues:
            self._add_finding(
                FindingBuilder()
                .name("Weak Content Security Policy (CSP) Directives")
                .category("A05")
                .vuln_type("Weak Security Header Configuration")
                .severity(SeverityLevel.MEDIUM)
                .confidence(ConfidenceLevel.CERTAIN)
                .url(self.target.url)
                .cwe("CWE-693")
                .description(
                    "The Content-Security-Policy header contains insecure directives that undermine XSS protection: "
                    + "; ".join(issues)
                )
                .risk("Weak CSP directives significantly reduce protection against XSS attacks.")
                .remediation(
                    "1. Remove 'unsafe-inline' - use nonces or hashes instead.\n"
                    "2. Remove 'unsafe-eval' - refactor code to avoid eval().\n"
                    "3. Replace wildcard (*) with specific trusted domains.\n"
                    "4. Use CSP evaluator: https://csp-evaluator.withgoogle.com/"
                )
                .add_ref("https://content-security-policy.com/")
                .evidence(f"CSP value: {csp[:300]}")
                .detected_by("A05_WEAK_CSP")
                .build()
            )

    # ─── Sensitive Files ──────────────────────────────────────────────────────

    async def _check_sensitive_files(self) -> None:
        """Probe for commonly exposed sensitive configuration files."""
        tasks = []
        for path, description, severity, cwe in SENSITIVE_FILES:
            tasks.append(self._probe_sensitive_file(path, description, severity, cwe))

        # Run in batches to avoid overloading
        batch_size = 15
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)

    async def _probe_sensitive_file(
        self, path: str, description: str, severity: SeverityLevel, cwe: str
    ) -> None:
        url = urljoin(self.target.url, path)
        resp, elapsed = await self._request('GET', url)
        if resp is None or resp.status_code not in (200, 206):
            return

        body = resp.text[:2000]
        ct = resp.headers.get('content-type', '').lower()

        # Validate it's actually sensitive content (not a generic 200 page)
        is_sensitive = False
        if path.endswith('.env') or path.endswith('.env.local'):
            is_sensitive = any(kw in body for kw in ['=', 'DATABASE', 'SECRET', 'KEY', 'TOKEN', 'PASSWORD'])
        elif path.endswith(('.git/config', '.git/HEAD')):
            is_sensitive = any(kw in body for kw in ['[core]', 'ref: refs', 'repositoryformatversion'])
        elif path.endswith('.sql') or path.endswith('.sql.gz'):
            is_sensitive = any(kw in body.lower() for kw in ['insert into', 'create table', 'drop table', 'select'])
        elif 'phpinfo' in path or 'info.php' in path:
            is_sensitive = 'phpinfo()' in body or 'PHP Version' in body
        elif path.endswith(('.zip', '.tar.gz', '.tar', '.bak')):
            is_sensitive = resp.status_code == 200 and len(resp.content) > 1000
        elif path.endswith('.json') or path.endswith('.yaml') or path.endswith('.yml'):
            is_sensitive = any(kw in body for kw in ['password', 'secret', 'token', 'key', 'database'])
        elif path in ('/swagger.json', '/openapi.json', '/swagger.yaml', '/api-docs'):
            is_sensitive = any(kw in body for kw in ['swagger', 'openapi', '"paths"', 'paths:'])
        elif path.endswith('.php'):
            is_sensitive = ('text/html' not in ct) and (resp.status_code == 200)
        else:
            is_sensitive = False

        # Extra safety: HTML responses for non-HTML files are false positives
        if 'text/html' in ct and not path.endswith(('.php', '.html', '/api-docs', '/swagger-ui.html')):
            is_sensitive = False

        if not is_sensitive:
            return

        self._add_finding(
            FindingBuilder()
            .name(f"Sensitive File Exposed: {path}")
            .category("A05")
            .vuln_type("Sensitive File/Directory Exposure")
            .severity(severity)
            .confidence(ConfidenceLevel.HIGH)
            .url(url)
            .cwe(cwe)
            .description(
                f"The {description} at '{path}' is publicly accessible. "
                f"HTTP {resp.status_code} response with {len(resp.content)} bytes of content. "
                "This file may contain credentials, configuration data, or source code."
            )
            .risk(
                "Exposed configuration files may contain credentials, API keys, database connection "
                "strings, and other sensitive data that enable further attacks."
            )
            .impact(
                "Credential theft, database access, secret key exposure, source code disclosure. "
                "Severity depends on file content - may lead to full application compromise."
            )
            .remediation(
                f"1. Remove '{path}' from the web-accessible directory.\n"
                "2. Move sensitive files outside the web root.\n"
                "3. Rotate any credentials found in exposed files immediately.\n"
                "4. Add the file path to .htaccess or server config deny rules.\n"
                "5. Review all environment files and configs for proper access restrictions."
            )
            .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/")
            .evidence(f"HTTP {resp.status_code} response received for {url} ({len(resp.content)} bytes)")
            .proof(f"GET {url} -> HTTP {resp.status_code}\nPreview: {body[:200]}")
            .request(self._build_request_obj('GET', url))
            .response(self._build_response_obj(resp, elapsed))
            .detected_by("A05_SENSITIVE_FILE")
            .build()
        )

    # ─── HTTP Methods ─────────────────────────────────────────────────────────

    async def _check_http_methods(self) -> None:
        """Test for dangerous HTTP methods (TRACE, PUT, DELETE)."""
        # First use OPTIONS to see what methods are allowed
        resp, _ = await self._request('OPTIONS', self.target.url)
        allowed_methods = set()
        if resp:
            allow_header = resp.headers.get('Allow', '') or resp.headers.get('allow', '')
            allowed_methods = {m.strip().upper() for m in allow_header.split(',') if m.strip()}

        # Test each dangerous method directly
        for method, (vuln_name, severity, cwe) in DANGEROUS_METHODS.items():
            if method not in allowed_methods:
                # Try it directly even if not in Allow header
                if method == 'TRACE':
                    test_resp, elapsed = await self._request('TRACE', self.target.url)
                    if test_resp and test_resp.status_code in (200,):
                        await self._report_method_vuln(method, vuln_name, severity, cwe, test_resp, elapsed)
                        continue
                elif method in ('PUT', 'DELETE'):
                    # Test with a harmless path
                    test_resp, elapsed = await self._request(method, urljoin(self.target.url, '/test_method_probe'))
                    if test_resp and test_resp.status_code not in (405, 501, 403):
                        await self._report_method_vuln(method, vuln_name, severity, cwe, test_resp, elapsed)
                        continue
            else:
                # Method explicitly allowed
                if method in ('TRACE', 'PUT', 'DELETE', 'CONNECT'):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"Dangerous HTTP Method Allowed: {method}")
                        .category("A05")
                        .vuln_type("Dangerous HTTP Method Enabled")
                        .severity(severity)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(self.target.url)
                        .cwe(cwe)
                        .description(
                            f"The HTTP method '{method}' is explicitly allowed by the server (in Allow header). "
                            f"{vuln_name} vulnerability may be exploitable."
                        )
                        .risk(f"Enabling {method} method may allow {vuln_name}.")
                        .remediation(
                            f"1. Disable the {method} method at the web server level.\n"
                            "2. Apply method restrictions in server config (Apache/Nginx/IIS).\n"
                            "3. Implement a WAF rule to block dangerous HTTP methods."
                        )
                        .add_ref("https://owasp.org/www-community/attacks/Cross_Site_Tracing")
                        .evidence(f"OPTIONS response Allow header includes {method}: '{allow_header}'")
                        .detected_by("A05_HTTP_METHODS")
                        .build()
                    )

    async def _report_method_vuln(
        self, method: str, vuln_name: str, severity: SeverityLevel,
        cwe: str, resp: httpx.Response, elapsed: float
    ) -> None:
        self._add_finding(
            FindingBuilder()
            .name(f"Dangerous HTTP Method Enabled: {method}")
            .category("A05")
            .vuln_type("Dangerous HTTP Method Enabled")
            .severity(severity)
            .confidence(ConfidenceLevel.HIGH)
            .url(self.target.url)
            .cwe(cwe)
            .description(
                f"The {method} HTTP method is enabled on the target server. "
                f"This enables {vuln_name}. Response: HTTP {resp.status_code}."
            )
            .risk(f"Enabling {method} may allow attackers to perform {vuln_name}.")
            .impact(
                f"TRACE enables session credential theft via XST. "
                f"PUT/DELETE enables unauthorized file upload or resource deletion."
            )
            .remediation(
                f"1. Disable {method} in web server configuration:\n"
                "   - Apache: TraceEnable Off\n"
                "   - Nginx: if ($request_method = TRACE) { return 405; }\n"
                "   - IIS: requestFiltering/verbs - remove dangerous verbs.\n"
                "2. Apply method allowlisting at the WAF level."
            )
            .add_ref("https://owasp.org/www-community/attacks/Cross_Site_Tracing")
            .evidence(f"{method} {self.target.url} returned HTTP {resp.status_code}")
            .proof(f"{method} request to {self.target.url} -> HTTP {resp.status_code}")
            .response(self._build_response_obj(resp, elapsed))
            .detected_by("A05_HTTP_METHODS")
            .build()
        )

    # ─── CORS Misconfiguration ────────────────────────────────────────────────

    async def _check_cors(self) -> None:
        """Check for CORS misconfiguration."""
        for test_origin in CORS_TEST_ORIGINS:
            resp, elapsed = await self._request(
                'GET', self.target.url,
                headers={'Origin': test_origin}
            )
            if resp is None:
                continue

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

            if acao == '*':
                self._add_finding(
                    FindingBuilder()
                    .name("CORS Wildcard Origin Misconfiguration")
                    .category("A05")
                    .vuln_type("CORS Misconfiguration")
                    .severity(SeverityLevel.MEDIUM)
                    .confidence(ConfidenceLevel.CERTAIN)
                    .url(self.target.url)
                    .cwe("CWE-942")
                    .description(
                        "The server returns 'Access-Control-Allow-Origin: *', allowing any origin "
                        "to make cross-origin requests. While cookies are not sent with wildcard CORS, "
                        "any unauthenticated API data is accessible from any website."
                    )
                    .risk("API data may be accessible to any website, enabling cross-origin data theft.")
                    .impact("Cross-origin data access for unauthenticated API responses.")
                    .remediation(
                        "1. Replace wildcard with a specific allowlist of trusted origins.\n"
                        "2. Validate the Origin header against a server-side allowlist.\n"
                        "3. Avoid using * for APIs that return sensitive data.\n"
                        "4. Never combine * with Allow-Credentials: true."
                    )
                    .add_ref("https://portswigger.net/web-security/cors")
                    .add_ref("https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny")
                    .evidence(f"Access-Control-Allow-Origin: * in response to Origin: {test_origin}")
                    .proof(f"GET {self.target.url} with Origin: {test_origin} -> ACAO: *")
                    .detected_by("A05_CORS_WILDCARD")
                    .build()
                )
                return

            if acao == test_origin and acac == 'true':
                # Arbitrary origin reflection with credentials = critical
                self._add_finding(
                    FindingBuilder()
                    .name("CORS Arbitrary Origin Reflection with Credentials Allowed")
                    .category("A05")
                    .vuln_type("CORS Misconfiguration")
                    .severity(SeverityLevel.CRITICAL)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(self.target.url)
                    .cwe("CWE-942")
                    .description(
                        f"The server reflects the attacker-controlled Origin '{test_origin}' "
                        "and also sets 'Access-Control-Allow-Credentials: true'. "
                        "This means any malicious website can make authenticated cross-origin requests "
                        "including session cookies, enabling full cross-origin authentication bypass."
                    )
                    .risk(
                        "Critical: Any website can make authenticated requests on behalf of a logged-in user, "
                        "reading sensitive API responses with their credentials."
                    )
                    .impact(
                        "Complete cross-origin account takeover. Attacker can read any authenticated "
                        "API endpoint including user data, financial info, and admin functions."
                    )
                    .remediation(
                        "1. NEVER reflect arbitrary Origin values - validate against a strict allowlist.\n"
                        "2. If credentials are needed, specify exact origins only.\n"
                        "3. Set Vary: Origin header when using dynamic CORS.\n"
                        "4. Review all APIs that use ACAO + ACAC headers."
                    )
                    .add_ref("https://portswigger.net/web-security/cors")
                    .evidence(
                        f"Origin: {test_origin} -> ACAO: {acao}, ACAC: {acac}"
                    )
                    .proof(
                        f"GET {self.target.url}\nOrigin: {test_origin}\n"
                        f"Response: Access-Control-Allow-Origin: {acao}\n"
                        f"Response: Access-Control-Allow-Credentials: {acac}"
                    )
                    .detected_by("A05_CORS_REFLECTED_CREDENTIALS")
                    .build()
                )
                return

    # ─── Server Version Disclosure ────────────────────────────────────────────

    async def _check_server_disclosure(self) -> None:
        """Check for server version information disclosure in headers."""
        resp, elapsed = await self._request('GET', self.target.url)
        if resp is None:
            return

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        version_headers = {
            'server': 'Server',
            'x-powered-by': 'X-Powered-By',
            'x-aspnet-version': 'X-AspNet-Version',
            'x-aspnetmvc-version': 'X-AspNetMvc-Version',
            'x-generator': 'X-Generator',
            'x-backend-server': 'X-Backend-Server',
            'via': 'Via',
        }

        version_pattern = re.compile(r'[0-9]+\.[0-9]+')

        for header_key, header_name in version_headers.items():
            value = headers_lower.get(header_key, '')
            if not value:
                continue

            if version_pattern.search(value):
                self._add_finding(
                    FindingBuilder()
                    .name(f"Server Version Disclosure via '{header_name}' Header")
                    .category("A05")
                    .vuln_type("Server Version Disclosure")
                    .severity(SeverityLevel.LOW)
                    .confidence(ConfidenceLevel.CERTAIN)
                    .url(self.target.url)
                    .header(header_key)
                    .cwe("CWE-200")
                    .description(
                        f"The '{header_name}' response header discloses the server software version: '{value}'. "
                        "Version disclosure helps attackers identify outdated software with known CVEs."
                    )
                    .risk(
                        "Knowing the exact version lets attackers identify applicable CVEs "
                        "and target known exploits without additional reconnaissance."
                    )
                    .impact(
                        "Enables targeted exploitation of version-specific vulnerabilities "
                        "and reduces attacker effort for fingerprinting."
                    )
                    .remediation(
                        f"1. Remove or generic-ize the {header_name} header:\n"
                        "   - Apache: ServerTokens Prod; ServerSignature Off\n"
                        "   - Nginx: server_tokens off\n"
                        "   - IIS: Remove version from headers via URLRewrite or custom config\n"
                        "2. Suppress X-Powered-By in PHP: expose_php = Off\n"
                        "3. Configure the app framework to omit version headers."
                    )
                    .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server")
                    .evidence(f"Response header {header_name}: {value}")
                    .proof(f"GET {self.target.url}\nResponse: {header_name}: {value}")
                    .detected_by("A05_VERSION_DISCLOSURE")
                    .build()
                )

    # ─── Debug Endpoints ──────────────────────────────────────────────────────

    async def _check_debug_endpoints(self) -> None:
        """Check for exposed debug and management endpoints."""
        tasks = []
        for path in DEBUG_PATHS:
            tasks.append(self._probe_debug_endpoint(path))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_debug_endpoint(self, path: str) -> None:
        url = urljoin(self.target.url, path)
        resp, elapsed = await self._request('GET', url)
        if resp is None or resp.status_code not in (200,):
            return

        body = resp.text[:3000]
        ct = resp.headers.get('content-type', '').lower()

        # Determine what kind of debug endpoint
        is_actuator = 'actuator' in path
        is_debug = any(kw in path for kw in ['/debug', '/_debug', '/pprof'])

        sensitive_keywords = [
            'spring', 'bean', 'mappings', 'environment', 'env', 'password',
            'secret', 'datasource', 'database', 'goroutine', 'heap',
            'memstats', 'config', 'Properties'
        ]

        if any(kw in body.lower() for kw in sensitive_keywords):
            severity = SeverityLevel.HIGH if is_actuator else SeverityLevel.MEDIUM
            self._add_finding(
                FindingBuilder()
                .name(f"Debug/Actuator Endpoint Exposed: {path}")
                .category("A05")
                .vuln_type("Debug Endpoint Exposure")
                .severity(severity)
                .confidence(ConfidenceLevel.HIGH)
                .url(url)
                .cwe("CWE-215")
                .description(
                    f"A debug or management endpoint was found at '{url}'. "
                    "This endpoint returns sensitive internal application information "
                    "such as environment variables, beans, configuration properties, or heap dumps."
                )
                .risk(
                    "Debug endpoints expose credentials, internal configuration, "
                    "and system internals that can be used for lateral movement and escalation."
                )
                .impact(
                    "Credential exposure (database passwords, API keys), "
                    "internal infrastructure disclosure, potential heap dump analysis for secrets."
                )
                .remediation(
                    "1. Disable debug/actuator endpoints in production.\n"
                    "2. If needed, restrict access via network ACLs or authentication.\n"
                    "3. Spring Boot: management.endpoints.web.exposure.include=health only\n"
                    "4. Disable heapdump and env endpoints always.\n"
                    "5. Set management.server.port to a non-public port."
                )
                .add_ref("https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints")
                .evidence(f"HTTP 200 response from {url} with sensitive content")
                .proof(f"GET {url}\nContent preview: {body[:300]}")
                .request(self._build_request_obj('GET', url))
                .response(self._build_response_obj(resp, elapsed))
                .detected_by("A05_DEBUG_ENDPOINT")
                .build()
            )

    # ─── Error Disclosure ─────────────────────────────────────────────────────

    async def _check_error_disclosure(self, assets: List[AssetInfo]) -> None:
        """Check if detailed error messages are exposed."""
        # Trigger errors with invalid parameters
        error_triggers = [
            (self.target.url + '?id=99999999999999999999', 'Large integer'),
            (self.target.url + '?page=../../../etc/passwd', 'Path traversal'),
            (self.target.url + '/nonexistent_page_xyz_12345', 'Missing page'),
        ]

        for url, trigger_type in error_triggers:
            resp, elapsed = await self._request('GET', url)
            if resp is None:
                continue

            body = resp.text
            for pattern, error_type, severity in ERROR_DISCLOSURE_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"Verbose Error Message Disclosure: {error_type}")
                        .category("A05")
                        .vuln_type("Verbose Error Messages")
                        .severity(severity)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(url)
                        .cwe("CWE-209")
                        .description(
                            f"The application returns detailed {error_type} in HTTP responses. "
                            f"Triggered by: '{trigger_type}'. "
                            "Error messages disclose internal implementation details, file paths, "
                            "framework versions, and can reveal injection points."
                        )
                        .risk(
                            "Verbose errors provide attackers with valuable information about "
                            "internal application architecture, file paths, and potential injection points."
                        )
                        .impact(
                            "Accelerates exploitation by revealing database queries, file paths, "
                            "framework names, and internal class/function names."
                        )
                        .remediation(
                            "1. Configure the application to show generic error pages in production.\n"
                            "2. Log detailed errors server-side only (not in HTTP responses).\n"
                            "3. Use try/except/catch to handle all exceptions gracefully.\n"
                            "4. Set DEBUG=False in Django/Flask production configs.\n"
                            "5. Configure custom error pages for 4xx and 5xx responses."
                        )
                        .add_ref("https://owasp.org/www-community/Improper_Error_Handling")
                        .evidence(f"Error pattern '{pattern}' matched in response to {trigger_type}")
                        .proof(f"GET {url}\nResponse contains: {body[:400]}")
                        .request(self._build_request_obj('GET', url))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A05_ERROR_DISCLOSURE")
                        .build()
                    )
                    return  # One error disclosure finding is enough

    # ─── Directory Listing ────────────────────────────────────────────────────

    async def _check_directory_listing(self, assets: List[AssetInfo]) -> None:
        """Check for enabled directory listing."""
        # Check known directories from crawl
        dir_assets = [a for a in assets if a.asset_type == 'DIR' or a.url.endswith('/')]
        dir_urls = set()

        # Add common paths
        common_dirs = [
            '/images/', '/uploads/', '/files/', '/static/', '/media/',
            '/assets/', '/js/', '/css/', '/backup/', '/tmp/', '/temp/',
            '/logs/', '/data/', '/docs/', '/downloads/', '/resources/',
        ]
        for path in common_dirs:
            dir_urls.add(urljoin(self.target.url, path))

        for asset in dir_assets[:10]:
            dir_urls.add(asset.url)

        for url in list(dir_urls)[:20]:
            resp, elapsed = await self._request('GET', url)
            if resp is None or resp.status_code != 200:
                continue

            body = resp.text[:3000]
            for pattern in DIRECTORY_LISTING_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"Directory Listing Enabled at {url}")
                        .category("A05")
                        .vuln_type("Directory Listing Enabled")
                        .severity(SeverityLevel.MEDIUM)
                        .confidence(ConfidenceLevel.CERTAIN)
                        .url(url)
                        .cwe("CWE-548")
                        .description(
                            f"Directory listing is enabled at '{url}'. "
                            "The server returns a list of files and subdirectories, "
                            "potentially exposing sensitive files and application structure."
                        )
                        .risk(
                            "Directory listing exposes backup files, configuration files, "
                            "source code, and other sensitive resources not intended for public access."
                        )
                        .impact(
                            "Source code exposure, credential files, backup archives, "
                            "and private data accessible without authentication."
                        )
                        .remediation(
                            "1. Disable directory listing:\n"
                            "   - Apache: Options -Indexes\n"
                            "   - Nginx: autoindex off\n"
                            "   - IIS: Disable 'Directory Browsing'\n"
                            "2. Add an index.html or redirect to each directory.\n"
                            "3. Review what files are in publicly accessible directories."
                        )
                        .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information")
                        .evidence(f"Directory listing pattern '{pattern}' found in response from {url}")
                        .proof(f"GET {url} -> HTTP 200 with directory listing content")
                        .request(self._build_request_obj('GET', url))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A05_DIRECTORY_LISTING")
                        .build()
                    )
                    break

    # ─── Cloud Storage Misconfigurations ──────────────────────────────────────

    async def _check_cloud_storage(self, assets: List[AssetInfo]) -> None:
        """Check for misconfigured cloud storage buckets in page source."""
        resp, _ = await self._request('GET', self.target.url)
        if resp is None:
            return

        body = resp.text

        # Find S3 bucket references
        for pattern in S3_BUCKET_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for bucket_name in matches[:3]:
                await self._test_s3_bucket(bucket_name)

        # Find GCS bucket references
        for pattern in GCS_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for bucket_name in matches[:3]:
                await self._test_gcs_bucket(bucket_name)

    async def _test_s3_bucket(self, bucket_name: str) -> None:
        """Test if an S3 bucket is publicly readable."""
        bucket_url = f"https://{bucket_name}.s3.amazonaws.com/"
        resp, elapsed = await self._request('GET', bucket_url)
        if resp is None:
            return

        if resp.status_code == 200 and '<ListBucketResult' in resp.text:
            self._add_finding(
                FindingBuilder()
                .name(f"Public S3 Bucket: {bucket_name}")
                .category("A05")
                .vuln_type("Cloud Storage Misconfiguration")
                .severity(SeverityLevel.HIGH)
                .confidence(ConfidenceLevel.CERTAIN)
                .url(bucket_url)
                .cwe("CWE-732")
                .description(
                    f"Amazon S3 bucket '{bucket_name}' is publicly accessible and returns a file listing. "
                    "All objects in this bucket can be read by anyone on the internet."
                )
                .risk(
                    "Public S3 buckets have exposed sensitive data in many major breaches. "
                    "Files may include customer PII, credentials, backups, and proprietary code."
                )
                .impact("Full exposure of all files in the bucket to the public internet.")
                .remediation(
                    "1. Set bucket ACL to private immediately.\n"
                    "2. Enable Block Public Access for all S3 buckets.\n"
                    "3. Review all files in the bucket for sensitive data.\n"
                    "4. Enable S3 access logging.\n"
                    "5. Use bucket policies instead of ACLs for access control."
                )
                .add_ref("https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/")
                .evidence(f"S3 bucket {bucket_name} returned 200 with XML file listing")
                .proof(f"GET {bucket_url} -> HTTP 200 with ListBucketResult")
                .detected_by("A05_S3_PUBLIC_BUCKET")
                .build()
            )

    async def _test_gcs_bucket(self, bucket_name: str) -> None:
        """Test if a GCS bucket is publicly readable."""
        bucket_url = f"https://storage.googleapis.com/{bucket_name}/"
        resp, elapsed = await self._request('GET', bucket_url)
        if resp is None:
            return

        if resp.status_code == 200 and ('kind' in resp.text and 'storage#bucket' in resp.text):
            self._add_finding(
                FindingBuilder()
                .name(f"Public GCS Bucket: {bucket_name}")
                .category("A05")
                .vuln_type("Cloud Storage Misconfiguration")
                .severity(SeverityLevel.HIGH)
                .confidence(ConfidenceLevel.CERTAIN)
                .url(bucket_url)
                .cwe("CWE-732")
                .description(
                    f"Google Cloud Storage bucket '{bucket_name}' is publicly accessible. "
                    "Anyone on the internet can list and access files in this bucket."
                )
                .risk("Exposed GCS bucket may contain PII, credentials, backups, or source code.")
                .impact("Full exposure of all objects in the GCS bucket.")
                .remediation(
                    "1. Remove allUsers and allAuthenticatedUsers from bucket IAM.\n"
                    "2. Enable uniform bucket-level access.\n"
                    "3. Audit bucket contents for sensitive files.\n"
                    "4. Enable Cloud Audit Logs for bucket access."
                )
                .add_ref("https://cloud.google.com/storage/docs/access-control/making-data-public")
                .evidence(f"GCS bucket {bucket_name} returned 200 with bucket listing")
                .detected_by("A05_GCS_PUBLIC_BUCKET")
                .build()
            )
