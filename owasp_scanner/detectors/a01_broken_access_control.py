"""
A01 - Broken Access Control Detector
======================================
Detects:
- IDOR (Insecure Direct Object Reference)
- Directory Traversal / Path Traversal
- Forced Browsing
- Missing Authorization
- Privilege Escalation indicators
- Admin Panel Exposure
- File Disclosure
- Sensitive Resource Access
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, parse_qsl

import httpx

from ..core import (
    AssetInfo, BaseDetector, Finding, FindingBuilder,
    SeverityLevel, ConfidenceLevel, HTTPRequest, HTTPResponse, RateLimiter
)

# ─── Sensitive Admin & Privileged Paths ───────────────────────────────────────
ADMIN_PATHS = [
    '/admin/', '/administrator/', '/admin/login', '/wp-admin/',
    '/wp-login.php', '/cpanel/', '/phpmyadmin/', '/pma/',
    '/adminer/', '/manage/', '/management/', '/manager/',
    '/backend/', '/staff/', '/superadmin/', '/controlpanel/',
    '/admin.php', '/admin.html', '/admin/index.php',
    '/user/admin', '/users/admin', '/dashboard/', '/console/',
]

# Sensitive file endpoints
SENSITIVE_FILES = [
    '/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/self/environ',
    '/windows/win.ini', '/windows/system32/drivers/etc/hosts',
    '/boot.ini', '../../../../etc/passwd', '../../../etc/passwd',
    '../../etc/passwd', '../etc/passwd',
]

# Directory traversal payloads
TRAVERSAL_PAYLOADS = [
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '..%2Fetc%2Fpasswd',
    '..%252Fetc%252Fpasswd',
    '....//....//etc/passwd',
    '%2e%2e%2fetc%2fpasswd',
    '..%c0%afafetc/passwd',
    '/%5C../%5C../%5C../etc/passwd',
]

# Patterns suggesting IDOR in URLs
IDOR_PARAM_PATTERNS = re.compile(
    r'\b(id|user_?id|account_?id|file_?id|doc_?id|order_?id|'
    r'invoice_?id|record_?id|profile_?id|customer_?id|uid|pid|oid|'
    r'item_?id|product_?id|report_?id|num|number|ref|uuid|guid)\b',
    re.IGNORECASE
)

# IDOR success patterns in response
IDOR_SUCCESS_PATTERNS = [
    r'"id"\s*:\s*\d+',
    r'"user"\s*:\s*\{',
    r'"account"\s*:\s*\{',
    r'"email"\s*:\s*"[^"]+@[^"]+"',
    r'"username"\s*:\s*"[^"]+"',
    r'"name"\s*:\s*"[^"]+"',
    r'"ssn"\s*:\s*',
    r'"credit_card"\s*:\s*',
    r'"password"\s*:\s*',
    r'"token"\s*:\s*"[^"]+"',
]

# Patterns in response body indicating traversal worked
TRAVERSAL_SUCCESS_PATTERNS = [
    r'root:[x*]:0:0',            # Linux /etc/passwd
    r'\[boot loader\]',          # Windows boot.ini
    r'^\[drivers\]',             # win.ini
    r'USERPROFILE=',             # Windows env
    r'PATH=/usr/bin',            # Linux env
    r'for 16-bit app support',   # win.ini
    r'<TITLE>phpinfo',           # phpinfo
]

# Auth bypass headers
AUTH_BYPASS_HEADERS = [
    {'X-Original-URL': '/admin/'},
    {'X-Rewrite-URL': '/admin/'},
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Forwarded-Host': 'localhost'},
    {'X-Remote-Addr': '127.0.0.1'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Remote-IP': '127.0.0.1'},
    {'X-Client-IP': '127.0.0.1'},
]


class BrokenAccessControlDetector(BaseDetector):
    """
    A01:2021 - Broken Access Control Detector.
    Performs active checks for IDOR, path traversal, forced browsing,
    admin panel exposure, and authorization bypass.
    """
    owasp_category = "A01"
    name = "Broken Access Control"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A01 detection on {len(assets)} assets")

        tasks = []
        # Check all URLs for admin/sensitive exposure
        for asset in assets:
            tasks.append(self._check_forced_browsing(asset))
            if IDOR_PARAM_PATTERNS.search(asset.url):
                tasks.append(self._check_idor(asset))

        # Check traversal on all assets with file/path parameters
        for asset in assets:
            for param_name in asset.params:
                if re.search(r'(file|path|dir|folder|include|load|page|template|doc|read)',
                             param_name, re.IGNORECASE):
                    tasks.append(self._check_traversal(asset, param_name))

        # Check for admin panel exposure
        tasks.append(self._check_admin_panels())

        # Check auth bypass via header manipulation
        for asset in assets:
            if asset.asset_type in ('AUTH_PAGE', 'DIR') and asset.status_code == 403:
                tasks.append(self._check_auth_bypass_headers(asset))

        await asyncio.gather(*tasks, return_exceptions=True)
        self._log(f"A01 detection complete. Found {len(self._findings)} issues.")
        return self._findings

    async def _check_admin_panels(self) -> None:
        """Probe common admin panel paths."""
        for path in ADMIN_PATHS:
            url = urljoin(self.target.url, path)
            resp, elapsed = await self._request('GET', url)
            if resp is None:
                continue

            if resp.status_code == 200:
                # Confirm it's actually an admin login page
                body = resp.text.lower()
                is_admin = any(kw in body for kw in [
                    'admin', 'login', 'password', 'username',
                    'dashboard', 'management', 'control panel'
                ])
                if is_admin:
                    f = (
                        FindingBuilder()
                        .name("Admin Panel Exposed Without Authentication")
                        .category("A01")
                        .vuln_type("Admin Panel Exposure")
                        .severity(SeverityLevel.HIGH)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(url)
                        .cwe("CWE-284")
                        .capec("CAPEC-1")
                        .description(
                            f"An administrative interface was discovered at {url} and is accessible "
                            "without requiring authentication or behind a protective gateway."
                        )
                        .risk("Exposed admin panels allow attackers to attempt credential attacks, "
                              "access privileged functionality, and potentially compromise the system.")
                        .impact("Full application compromise if admin credentials are weak or default. "
                                "Data exfiltration, configuration changes, user management access.")
                        .remediation(
                            "1. Restrict admin panel access by IP allowlist.\n"
                            "2. Require MFA for all administrative accounts.\n"
                            "3. Move admin interface to a separate authenticated subdomain.\n"
                            "4. Implement rate limiting on login attempts."
                        )
                        .add_ref("https://owasp.org/Top10/A01_2021-Broken_Access_Control/")
                        .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/")
                        .evidence(f"HTTP {resp.status_code} response with admin keywords in body")
                        .proof(f"GET {url} returned HTTP 200 with admin panel content")
                        .request(self._build_request_obj('GET', url))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A01_ADMIN_PANEL_CHECK")
                        .build()
                    )
                    self._add_finding(f)

    async def _check_idor(self, asset: AssetInfo) -> None:
        """
        Check for IDOR by mutating numeric IDs in URL parameters
        and comparing responses.
        """
        parsed = urlparse(asset.url)
        params = dict(parse_qsl(parsed.query))

        for param_name, param_value in params.items():
            if not IDOR_PARAM_PATTERNS.search(param_name):
                continue
            if not param_value.isdigit():
                continue

            original_id = int(param_value)
            # Try adjacent IDs
            test_ids = [original_id - 1, original_id + 1, original_id + 100,
                        1, 2, 9999, 0]

            # Get baseline response
            baseline_resp, _ = await self._request('GET', asset.url)
            if baseline_resp is None or baseline_resp.status_code not in (200, 201):
                continue

            baseline_len = len(baseline_resp.text)

            for test_id in test_ids:
                if test_id == original_id or test_id < 0:
                    continue

                # Build test URL
                test_params = {**params, param_name: str(test_id)}
                test_url = parsed._replace(
                    query=urlencode(test_params)
                ).geturl()

                test_resp, elapsed = await self._request('GET', test_url)
                if test_resp is None:
                    continue

                # IDOR check: 200 response with different content = potentially exposing another object
                if test_resp.status_code == 200:
                    test_len = len(test_resp.text)
                    body = test_resp.text

                    # Check for PII / sensitive patterns in response
                    sensitive_found = []
                    for pattern in IDOR_SUCCESS_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            sensitive_found.append(pattern)

                    if sensitive_found and abs(test_len - baseline_len) > 50:
                        f = (
                            FindingBuilder()
                            .name(f"IDOR - {param_name} Parameter Allows Access to Different Objects")
                            .category("A01")
                            .vuln_type("IDOR")
                            .severity(SeverityLevel.HIGH)
                            .confidence(ConfidenceLevel.MEDIUM)
                            .url(test_url)
                            .param(param_name)
                            .cwe("CWE-639")
                            .capec("CAPEC-194")
                            .description(
                                f"The parameter '{param_name}' appears to be used as a direct object "
                                f"reference. Changing the value from {original_id} to {test_id} "
                                "returned a different 200 response with sensitive data patterns, "
                                "suggesting IDOR vulnerability."
                            )
                            .risk("Attackers can enumerate object IDs to access data belonging "
                                  "to other users, bypassing authorization controls.")
                            .impact("Unauthorized access to user data, account information, "
                                    "orders, files, or any resource referenced by sequential IDs.")
                            .remediation(
                                "1. Implement server-side authorization checks on every resource access.\n"
                                "2. Use indirect object references (UUID/GUID instead of sequential IDs).\n"
                                "3. Verify ownership before returning any object data.\n"
                                "4. Log and alert on object access pattern anomalies."
                            )
                            .add_ref("https://portswigger.net/web-security/access-control/idor")
                            .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References")
                            .evidence(
                                f"Changing {param_name}={original_id} to {param_name}={test_id} "
                                f"returned HTTP 200 with patterns: {sensitive_found[:2]}"
                            )
                            .proof(
                                f"Original: GET {asset.url} -> {baseline_resp.status_code} ({baseline_len} bytes)\n"
                                f"Test: GET {test_url} -> {test_resp.status_code} ({test_len} bytes)"
                            )
                            .request(self._build_request_obj('GET', test_url))
                            .response(self._build_response_obj(test_resp, elapsed))
                            .detected_by("A01_IDOR_CHECK")
                            .build()
                        )
                        self._add_finding(f)
                        break  # One finding per param is enough

    async def _check_traversal(self, asset: AssetInfo, param_name: str) -> None:
        """Test for directory/path traversal in a file parameter."""
        for payload in TRAVERSAL_PAYLOADS:
            test_url = self._inject_param(asset.url, param_name, payload)
            resp, elapsed = await self._request('GET', test_url)
            if resp is None:
                continue

            body = resp.text
            for success_pattern in TRAVERSAL_SUCCESS_PATTERNS:
                if re.search(success_pattern, body, re.IGNORECASE | re.MULTILINE):
                    f = (
                        FindingBuilder()
                        .name(f"Path Traversal in Parameter '{param_name}'")
                        .category("A01")
                        .vuln_type("Directory Traversal")
                        .severity(SeverityLevel.HIGH)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(test_url)
                        .param(param_name)
                        .cwe("CWE-22")
                        .capec("CAPEC-126")
                        .description(
                            f"The parameter '{param_name}' is vulnerable to path traversal. "
                            f"The payload '{payload}' caused the server to return sensitive "
                            "system file content in the response."
                        )
                        .risk("Attackers can read arbitrary files from the server filesystem, "
                              "including configuration files, credentials, SSH keys, and source code.")
                        .impact("Full file system read access. May lead to credential theft, "
                                "source code disclosure, and further exploitation.")
                        .remediation(
                            "1. Validate and sanitize all file path inputs.\n"
                            "2. Use a whitelist of allowed paths/filenames.\n"
                            "3. Resolve to canonical path and verify it starts with allowed base directory.\n"
                            "4. Avoid passing user-controlled data to file system APIs."
                        )
                        .add_ref("https://owasp.org/www-community/attacks/Path_Traversal")
                        .add_ref("https://portswigger.net/web-security/file-path-traversal")
                        .evidence(f"Pattern '{success_pattern}' found in response with payload '{payload}'")
                        .proof(f"GET {test_url} returned file system content: {body[:200]}")
                        .request(self._build_request_obj('GET', test_url))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A01_TRAVERSAL_CHECK")
                        .build()
                    )
                    self._add_finding(f)
                    return  # One confirmed finding per param

    async def _check_forced_browsing(self, asset: AssetInfo) -> None:
        """Check if resources return 403/401 that can be bypassed."""
        if asset.status_code not in (401, 403):
            return

        url = asset.url
        # Try common forced browsing bypasses
        bypass_urls = [
            url + '/',
            url + '/./',
            url + '/.',
            url + '..;/',
            url + '%2f',
            url + '?',
        ]

        for burl in bypass_urls:
            resp, elapsed = await self._request('GET', burl)
            if resp and resp.status_code == 200:
                f = (
                    FindingBuilder()
                    .name(f"Forced Browsing Bypass - Authorization Bypass at {url}")
                    .category("A01")
                    .vuln_type("Forced Browsing")
                    .severity(SeverityLevel.HIGH)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(burl)
                    .cwe("CWE-425")
                    .capec("CAPEC-87")
                    .description(
                        f"The URL {url} returned HTTP {asset.status_code} (access denied), "
                        f"but the modified URL {burl} returned HTTP 200, indicating "
                        "the authorization check can be bypassed with URL manipulation."
                    )
                    .risk("Attackers can access restricted content by appending special characters "
                          "to URLs, bypassing frontend and some backend authorization checks.")
                    .impact("Unauthorized access to restricted pages, admin functionality, "
                            "or sensitive content.")
                    .remediation(
                        "1. Perform authorization checks on the resolved canonical path.\n"
                        "2. Normalize URLs server-side before applying ACLs.\n"
                        "3. Use framework-level authorization that is not affected by URL tricks.\n"
                        "4. Test authorization with canonicalized paths."
                    )
                    .evidence(f"GET {url} -> {asset.status_code}; GET {burl} -> 200")
                    .proof(f"URL: {burl}\nReturned: HTTP 200 ({len(resp.text)} bytes)")
                    .request(self._build_request_obj('GET', burl))
                    .response(self._build_response_obj(resp, elapsed))
                    .detected_by("A01_FORCED_BROWSE_CHECK")
                    .build()
                )
                self._add_finding(f)
                return

    async def _check_auth_bypass_headers(self, asset: AssetInfo) -> None:
        """Test if 403 responses can be bypassed via header injection."""
        for headers in AUTH_BYPASS_HEADERS:
            resp, elapsed = await self._request('GET', asset.url, headers=headers)
            if resp and resp.status_code == 200:
                header_str = ', '.join(f'{k}: {v}' for k, v in headers.items())
                f = (
                    FindingBuilder()
                    .name(f"Authorization Bypass via HTTP Header Manipulation")
                    .category("A01")
                    .vuln_type("Missing Authorization")
                    .severity(SeverityLevel.HIGH)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(asset.url)
                    .cwe("CWE-284")
                    .capec("CAPEC-1")
                    .description(
                        f"The resource at {asset.url} returned HTTP 403 on a normal request, "
                        f"but returned HTTP 200 when the request included the header(s): {header_str}. "
                        "This indicates the server is making authorization decisions based on "
                        "user-controllable HTTP headers."
                    )
                    .risk("Attackers can spoof internal IP addresses or override URL routing "
                          "by sending forged HTTP headers, bypassing IP-based restrictions.")
                    .impact("Access to admin interfaces, internal APIs, or restricted resources "
                            "that should only be accessible from trusted networks.")
                    .remediation(
                        "1. Never use X-Forwarded-For or similar headers for authorization decisions.\n"
                        "2. If using a load balancer, only trust headers from the balancer's IP.\n"
                        "3. Implement authorization at the application layer, not based on IP headers."
                    )
                    .evidence(f"Adding header '{header_str}' changed 403 response to 200")
                    .detected_by("A01_HEADER_BYPASS_CHECK")
                    .build()
                )
                self._add_finding(f)
                return

    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        """Inject a value into a URL parameter."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[param_name] = value
        return parsed._replace(query=urlencode(params)).geturl()
