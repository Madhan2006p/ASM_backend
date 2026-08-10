"""
A10 - Server-Side Request Forgery (SSRF) Detector
A04 - Insecure Design
A08 - Software and Data Integrity Failures
A09 - Security Logging and Monitoring Failures
====================================================
Combined detector for remaining OWASP categories.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl

import httpx

from ..core import (
    AssetInfo, BaseDetector, Finding, FindingBuilder,
    SeverityLevel, ConfidenceLevel
)


# ─── A10 SSRF ────────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    # Cloud metadata
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://169.254.169.254/metadata/v1/maintenance',
    'http://100.100.100.200/latest/meta-data/',  # Alibaba Cloud
    # Internal services
    'http://localhost/',
    'http://127.0.0.1/',
    'http://[::1]/',
    'http://0.0.0.0/',
    'http://2130706433/',   # 127.0.0.1 as decimal
    # Internal ranges
    'http://192.168.1.1/',
    'http://10.0.0.1/',
    'http://172.16.0.1/',
]

SSRF_URL_PARAMS = re.compile(
    r'\b(url|uri|link|src|source|dest|destination|redirect|return|next|'
    r'callback|feed|host|target|proxy|fetch|load|request|api|endpoint|'
    r'webhook|forward|import|file|path|image|img|media|document|attachment)\b',
    re.IGNORECASE
)

SSRF_SUCCESS_PATTERNS = [
    r'"instanceId"',                    # AWS EC2 metadata
    r'"ami-[a-f0-9]+"',                # AWS AMI ID
    r'security-credentials',            # AWS credentials
    r'"project":\s*\{',                # GCP metadata
    r'169\.254\.169\.254',              # IP in response body
    r'compute\.internal',               # Internal hostname
    r'"metadata":\s*\{',               # Generic metadata
]


class SSRFDetector(BaseDetector):
    """A10:2021 - SSRF Detector."""
    owasp_category = "A10"
    name = "SSRF"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A10 (SSRF) detection on {len(assets)} assets")
        tasks = []
        for asset in assets:
            for param_name in asset.params:
                if SSRF_URL_PARAMS.search(param_name):
                    tasks.append(self._test_ssrf_param(asset, param_name))
            for form in asset.forms:
                for inp in form.get('inputs', []):
                    if SSRF_URL_PARAMS.search(inp.get('name', '')):
                        tasks.append(self._test_ssrf_form(form, inp['name'], asset.url))

        # Also test any API endpoints that accept URL-like params
        api_assets = [a for a in assets if a.asset_type == 'API']
        for asset in api_assets:
            tasks.append(self._test_ssrf_api(asset))

        await asyncio.gather(*tasks, return_exceptions=True)
        self._log(f"A10 done. Found {len(self._findings)} issues.")
        return self._findings

    async def _test_ssrf_param(self, asset: AssetInfo, param_name: str) -> None:
        """Test URL parameter for SSRF."""
        parsed = urlparse(asset.url)
        params = dict(parse_qsl(parsed.query))

        for payload in SSRF_PAYLOADS[:6]:
            test_params = {**params, param_name: payload}
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            resp, elapsed = await self._request('GET', test_url)
            if resp is None:
                continue

            body = resp.text
            for pattern in SSRF_SUCCESS_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    f = (
                        FindingBuilder()
                        .name(f"Server-Side Request Forgery (SSRF) in Parameter '{param_name}'")
                        .category("A10")
                        .vuln_type("SSRF")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(test_url)
                        .param(param_name)
                        .cwe("CWE-918")
                        .capec("CAPEC-664")
                        .description(
                            f"SSRF confirmed in parameter '{param_name}'. "
                            f"The payload '{payload}' caused the server to make an "
                            f"outbound request and return internal cloud metadata."
                        )
                        .risk("SSRF allows attackers to make the server issue requests to internal services, "
                              "cloud metadata APIs, and internal network resources.")
                        .impact(
                            "Cloud credential theft (AWS/GCP keys via metadata), "
                            "internal network scanning, access to internal services, "
                            "potential RCE via internal service abuse."
                        )
                        .remediation(
                            "1. Validate URLs against an allowlist of permitted hosts.\\n"
                            "2. Block requests to private IP ranges (RFC 1918).\\n"
                            "3. Disable unnecessary URL-fetching functionality.\\n"
                            "4. Use a firewall to prevent server from making outbound requests.\\n"
                            "5. Implement IMDSv2 on AWS to require session tokens for metadata."
                        )
                        .add_ref("https://portswigger.net/web-security/ssrf")
                        .add_ref("https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/")
                        .evidence(f"Pattern '{pattern}' found in response to SSRF payload '{payload}'")
                        .proof(f"GET {test_url}\\nResponse body contains cloud metadata: {body[:300]}")
                        .request(self._build_request_obj('GET', test_url))
                        .response(self._build_response_obj(resp, elapsed))
                        .detected_by("A10_SSRF")
                        .build()
                    )
                    self._add_finding(f)
                    return

    async def _test_ssrf_form(self, form: Dict, param_name: str, base_url: str) -> None:
        """Test form input for SSRF."""
        action = form.get('action', base_url)
        method = form.get('method', 'POST')
        inputs = form.get('inputs', [])
        base_data = {i['name']: i.get('value', '') for i in inputs if i.get('name')}

        for payload in SSRF_PAYLOADS[:4]:
            data = {**base_data, param_name: payload}
            resp, elapsed = await self._request(method, action, data=data)
            if resp is None:
                continue

            for pattern in SSRF_SUCCESS_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    f = (
                        FindingBuilder()
                        .name(f"SSRF via Form Parameter '{param_name}'")
                        .category("A10")
                        .vuln_type("SSRF")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(action)
                        .param(param_name)
                        .cwe("CWE-918")
                        .description(f"SSRF confirmed via form parameter '{param_name}' at {action}.")
                        .remediation("Validate all URL inputs against an allowlist of permitted hosts.")
                        .evidence(f"SSRF payload returned cloud metadata in form submission response")
                        .detected_by("A10_SSRF_FORM")
                        .build()
                    )
                    self._add_finding(f)
                    return

    async def _test_ssrf_api(self, asset: AssetInfo) -> None:
        """Test API endpoints for SSRF via JSON body."""
        # Try posting a URL payload to API endpoints
        for payload in SSRF_PAYLOADS[:3]:
            resp, elapsed = await self._request(
                'POST', asset.url,
                json={'url': payload, 'link': payload, 'target': payload},
                headers={'Content-Type': 'application/json'}
            )
            if resp is None:
                continue

            for pattern in SSRF_SUCCESS_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    f = (
                        FindingBuilder()
                        .name(f"SSRF via API JSON Body at {asset.url}")
                        .category("A10")
                        .vuln_type("SSRF")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(asset.url)
                        .cwe("CWE-918")
                        .description(f"SSRF via JSON body parameters at API endpoint {asset.url}.")
                        .remediation("Validate URL fields in API request bodies against an allowlist.")
                        .detected_by("A10_SSRF_API")
                        .build()
                    )
                    self._add_finding(f)
                    return


# ─── A04 Insecure Design ─────────────────────────────────────────────────────

class InsecureDesignDetector(BaseDetector):
    """
    A04:2021 - Insecure Design Detector.
    Detects design-level issues that cannot be fixed by implementation alone.
    """
    owasp_category = "A04"
    name = "Insecure Design"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A04 detection")
        tasks = [
            self._check_mass_assignment(assets),
            self._check_rate_limiting(assets),
            self._check_insecure_workflows(assets),
            self._check_graphql_introspection(assets),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        self._log(f"A04 done. Found {len(self._findings)} issues.")
        return self._findings

    async def _check_mass_assignment(self, assets: List[AssetInfo]) -> None:
        """Test for mass assignment / over-posting vulnerabilities."""
        api_assets = [a for a in assets if a.asset_type == 'API' and a.method in ('POST', 'PUT', 'PATCH')]
        for asset in api_assets[:5]:
            # Try adding privileged fields to POST body
            priv_payloads = [
                {'role': 'admin', 'is_admin': True, 'admin': 1},
                {'isAdmin': True, 'admin': True, 'privilege': 'superuser'},
                {'role': 'superuser', 'permissions': ['admin'], 'group': 'admin'},
            ]
            for payload in priv_payloads:
                resp, _ = await self._request(
                    'POST', asset.url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )
                if resp and resp.status_code in (200, 201):
                    body = resp.text
                    if any(f'"{k}"' in body for k in payload):
                        # Check if injected fields appear in the response
                        for k, v in payload.items():
                            if f'"{k}"' in body and ('true' in body.lower() or 'admin' in body.lower()):
                                f = (
                                    FindingBuilder()
                                    .name(f"Mass Assignment / Over-Posting at {asset.url}")
                                    .category("A04")
                                    .vuln_type("Mass Assignment")
                                    .severity(SeverityLevel.HIGH)
                                    .confidence(ConfidenceLevel.MEDIUM)
                                    .url(asset.url)
                                    .cwe("CWE-915")
                                    .description(
                                        f"The API at {asset.url} may be vulnerable to mass assignment. "
                                        f"Privileged field '{k}' in the request body was accepted and "
                                        "reflected in the response."
                                    )
                                    .risk("Mass assignment allows attackers to modify properties they "
                                          "should not have access to, such as role, admin flag, or permissions.")
                                    .impact("Privilege escalation, unauthorized account modification.")
                                    .remediation(
                                        "1. Use explicit allow-lists (DTOs) for all model fields.\\n"
                                        "2. Never bind request body directly to database models.\\n"
                                        "3. Validate field names and values before processing."
                                    )
                                    .evidence(f"Field '{k}' was accepted and reflected in response")
                                    .detected_by("A04_MASS_ASSIGNMENT")
                                    .build()
                                )
                                self._add_finding(f)
                                break

    async def _check_rate_limiting(self, assets: List[AssetInfo]) -> None:
        """Check for missing rate limiting on sensitive APIs."""
        sensitive_apis = [a for a in assets if a.asset_type == 'API' and
                          any(kw in a.url.lower() for kw in ['search', 'query', 'list', 'users', 'email'])]

        for asset in sensitive_apis[:3]:
            # Send 20 rapid requests and check for rate limiting
            responses = []
            for _ in range(20):
                resp, _ = await self._request('GET', asset.url)
                if resp:
                    responses.append(resp.status_code)

            rate_limited = any(code in (429, 503) for code in responses)
            if not rate_limited and len(responses) >= 15:
                f = (
                    FindingBuilder()
                    .name(f"Missing Rate Limiting on API: {asset.url}")
                    .category("A04")
                    .vuln_type("Missing Rate Limiting")
                    .severity(SeverityLevel.MEDIUM)
                    .confidence(ConfidenceLevel.MEDIUM)
                    .url(asset.url)
                    .cwe("CWE-770")
                    .description(
                        f"The API endpoint {asset.url} does not appear to implement rate limiting. "
                        "20 rapid requests were sent without receiving a 429 response."
                    )
                    .risk("Without rate limiting, APIs are vulnerable to enumeration, brute force, "
                          "and resource exhaustion attacks.")
                    .remediation(
                        "1. Implement rate limiting (e.g., 100 req/min per IP).\\n"
                        "2. Return HTTP 429 with Retry-After header when rate limited.\\n"
                        "3. Use exponential backoff for repeat offenders."
                    )
                    .evidence(f"20 requests to {asset.url} all returned non-429 responses: {set(responses)}")
                    .detected_by("A04_RATE_LIMIT")
                    .build()
                )
                self._add_finding(f)

    async def _check_insecure_workflows(self, assets: List[AssetInfo]) -> None:
        """Check for insecure business logic in multi-step processes."""
        # Look for multi-step checkout or registration workflows
        checkout_patterns = ['/checkout', '/order', '/payment', '/purchase']
        for pattern in checkout_patterns:
            direct_urls = [a.url for a in assets if pattern in a.url.lower()]
            if len(direct_urls) > 1:
                # Check if later steps can be accessed directly
                for url in direct_urls[1:]:
                    resp, _ = await self._request('GET', url)
                    if resp and resp.status_code == 200:
                        body = resp.text.lower()
                        if any(kw in body for kw in ['confirm', 'submit', 'payment', 'credit card']):
                            f = (
                                FindingBuilder()
                                .name(f"Potential Insecure Workflow: Direct Access to {url}")
                                .category("A04")
                                .vuln_type("Insecure Business Logic")
                                .severity(SeverityLevel.MEDIUM)
                                .confidence(ConfidenceLevel.LOW)
                                .url(url)
                                .cwe("CWE-840")
                                .description(
                                    f"Multi-step workflow step at {url} is directly accessible. "
                                    "Manual testing required to verify if workflow steps can be skipped."
                                )
                                .remediation(
                                    "1. Validate all prerequisite steps server-side before allowing access.\\n"
                                    "2. Use server-side session state to track workflow progress.\\n"
                                    "3. Never rely on client-side state for business-critical workflows."
                                )
                                .detected_by("A04_WORKFLOW")
                                .build()
                            )
                            self._add_finding(f)

    async def _check_graphql_introspection(self, assets: List[AssetInfo]) -> None:
        """Check if GraphQL introspection is enabled in production."""
        gql_paths = ['/graphql', '/api/graphql', '/gql', '/query']
        for path in gql_paths:
            url = urljoin(self.target.url, path)
            introspection_query = '{"query": "{ __schema { types { name } } }"}'
            resp, _ = await self._request(
                'POST', url,
                content=introspection_query,
                headers={'Content-Type': 'application/json'}
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if 'data' in data and '__schema' in str(data):
                        f = (
                            FindingBuilder()
                            .name("GraphQL Introspection Enabled in Production")
                            .category("A04")
                            .vuln_type("GraphQL Introspection")
                            .severity(SeverityLevel.MEDIUM)
                            .confidence(ConfidenceLevel.CERTAIN)
                            .url(url)
                            .cwe("CWE-200")
                            .description(
                                f"GraphQL introspection is enabled at {url}. "
                                "Introspection exposes the complete API schema including all types, "
                                "queries, mutations, and field names."
                            )
                            .risk("Schema exposure provides attackers with a complete roadmap "
                                  "for the API, enabling targeted attacks on sensitive operations.")
                            .impact("API enumeration, discovery of hidden operations and sensitive fields.")
                            .remediation(
                                "1. Disable GraphQL introspection in production.\\n"
                                "2. Implement field-level access controls.\\n"
                                "3. Use query depth/complexity limits."
                            )
                            .add_ref("https://graphql.org/learn/introspection/")
                            .evidence(f"Introspection query at {url} returned __schema data")
                            .detected_by("A04_GRAPHQL")
                            .build()
                        )
                        self._add_finding(f)
                        return
                except Exception:
                    pass


# ─── A08 Data Integrity Failures ─────────────────────────────────────────────

class DataIntegrityFailuresDetector(BaseDetector):
    """A08:2021 - Software and Data Integrity Failures."""
    owasp_category = "A08"
    name = "Data Integrity Failures"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A08 detection")
        tasks = [
            self._check_subresource_integrity(assets),
            self._check_deserialization(assets),
            self._check_dependency_confusion(assets),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._findings

    async def _check_subresource_integrity(self, assets: List[AssetInfo]) -> None:
        """Check if external scripts/styles lack SRI attributes."""
        resp, _ = await self._request('GET', self.target.url)
        if resp is None:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Check external scripts and stylesheets
            external_resources = []
            for tag in soup.find_all(['script', 'link'], src=True):
                src = tag.get('src', '')
                if src.startswith('http') and urlparse(src).netloc != urlparse(self.target.url).netloc:
                    sri = tag.get('integrity', '')
                    if not sri:
                        external_resources.append(src)

            for tag in soup.find_all('link', rel='stylesheet', href=True):
                href = tag.get('href', '')
                if href.startswith('http') and urlparse(href).netloc != urlparse(self.target.url).netloc:
                    sri = tag.get('integrity', '')
                    if not sri:
                        external_resources.append(href)

            if external_resources:
                f = (
                    FindingBuilder()
                    .name(f"Missing Subresource Integrity (SRI) on {len(external_resources)} External Resources")
                    .category("A08")
                    .vuln_type("Missing SRI")
                    .severity(SeverityLevel.MEDIUM)
                    .confidence(ConfidenceLevel.CERTAIN)
                    .url(self.target.url)
                    .cwe("CWE-353")
                    .description(
                        f"{len(external_resources)} external scripts/stylesheets are loaded without "
                        "Subresource Integrity (SRI) hashes. If the CDN is compromised, "
                        "malicious code would be loaded silently."
                    )
                    .risk("CDN compromise or man-in-the-middle on CDN content can inject "
                          "malicious code into the page.")
                    .impact("Complete client-side compromise if CDN is attacked. Credential theft, "
                            "session hijacking, malware distribution.")
                    .remediation(
                        "1. Add integrity and crossorigin attributes to all external resources.\\n"
                        "2. Use SRI hash generator: https://www.srihash.org/\\n"
                        "3. Pin to specific CDN resource versions.\\n"
                        "4. Consider self-hosting critical libraries."
                    )
                    .add_ref("https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity")
                    .evidence(f"External resources without SRI:\\n" + "\\n".join(external_resources[:5]))
                    .detected_by("A08_SRI_CHECK")
                    .build()
                )
                self._add_finding(f)
        except Exception:
            pass

    async def _check_deserialization(self, assets: List[AssetInfo]) -> None:
        """Check for insecure deserialization indicators."""
        # Common deserialization endpoints
        deser_indicators = [
            # Java serialized object magic bytes (base64 encoded: rO0ABX)
            'rO0ABX', 'aced0005',
            # PHP serialized objects
            'O:8:', 'a:2:', 's:6:',
            # Python pickle
            '\\x80\\x02',
        ]

        for asset in assets:
            if asset.method in ('POST', 'PUT'):
                for param_val in asset.params.values():
                    for indicator in deser_indicators:
                        if indicator.lower() in str(param_val).lower():
                            f = (
                                FindingBuilder()
                                .name(f"Potential Insecure Deserialization Input at {asset.url}")
                                .category("A08")
                                .vuln_type("Insecure Deserialization")
                                .severity(SeverityLevel.HIGH)
                                .confidence(ConfidenceLevel.LOW)
                                .url(asset.url)
                                .cwe("CWE-502")
                                .capec("CAPEC-586")
                                .description(
                                    f"Serialized object indicators ('{indicator}') found in request parameters. "
                                    "Manual testing required to confirm insecure deserialization."
                                )
                                .risk("Insecure deserialization can lead to Remote Code Execution.")
                                .remediation(
                                    "1. Do not deserialize untrusted data.\\n"
                                    "2. Use digital signatures to verify serialized data integrity.\\n"
                                    "3. Prefer safe formats like JSON/XML over binary serialization."
                                )
                                .detected_by("A08_DESERIALIZE")
                                .build()
                            )
                            self._add_finding(f)
                            break

    async def _check_dependency_confusion(self, assets: List[AssetInfo]) -> None:
        """Check for package.json exposure (dependency confusion risk)."""
        pkg_paths = ['/package.json', '/package-lock.json', '/composer.json',
                     '/requirements.txt', '/Gemfile', '/pom.xml']
        for path in pkg_paths:
            url = urljoin(self.target.url, path)
            resp, _ = await self._request('GET', url)
            if resp and resp.status_code == 200:
                body = resp.text
                if any(kw in body for kw in ['"dependencies"', '"require"', 'gem ', 'import ']):
                    f = (
                        FindingBuilder()
                        .name(f"Dependency Manifest Exposed: {path}")
                        .category("A08")
                        .vuln_type("Supply Chain Risk")
                        .severity(SeverityLevel.LOW)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(url)
                        .cwe("CWE-538")
                        .description(
                            f"Dependency manifest file '{path}' is publicly accessible. "
                            "This exposes exact package names and versions, enabling "
                            "targeted dependency confusion attacks."
                        )
                        .risk("Dependency confusion attacks can inject malicious packages into the build.")
                        .remediation(
                            "1. Restrict access to build/dependency files.\\n"
                            "2. Move these files outside web root.\\n"
                            "3. Implement private package registries.\\n"
                            "4. Use npm/pip --prefix configuration."
                        )
                        .detected_by("A08_DEP_CONFUSION")
                        .build()
                    )
                    self._add_finding(f)


# ─── A09 Logging and Monitoring Failures ─────────────────────────────────────

class LoggingMonitoringDetector(BaseDetector):
    """A09:2021 - Security Logging and Monitoring Failures."""
    owasp_category = "A09"
    name = "Logging and Monitoring Failures"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A09 detection")
        tasks = [
            self._check_error_logging(),
            self._check_log_exposure(assets),
            self._check_audit_trail(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._findings

    async def _check_error_logging(self) -> None:
        """Check if errors are logged and if logging is misconfigured."""
        # Send invalid request and see if response contains debug/stack info
        error_urls = [
            self.target.url + "?debug=1",
            self.target.url + "?verbose=true",
            self.target.url + "?trace=1",
            self.target.url + "?test_error=1&throw=1",
        ]
        for url in error_urls:
            resp, _ = await self._request('GET', url)
            if resp and resp.status_code == 200:
                body = resp.text
                if re.search(r'debug.*true|verbose.*on|log.*level.*debug', body, re.IGNORECASE):
                    f = (
                        FindingBuilder()
                        .name("Debug Mode Enabled via URL Parameter")
                        .category("A09")
                        .vuln_type("Debug Mode Enabled")
                        .severity(SeverityLevel.MEDIUM)
                        .confidence(ConfidenceLevel.MEDIUM)
                        .url(url)
                        .cwe("CWE-778")
                        .description(
                            "Debug mode appears to be enabled via a URL parameter. "
                            "This may expose verbose logging, stack traces, or internal state."
                        )
                        .remediation(
                            "1. Remove debug parameters from production.\\n"
                            "2. Never allow debug mode to be toggled via URL.\\n"
                            "3. Set debug=False in production configs."
                        )
                        .detected_by("A09_DEBUG_MODE")
                        .build()
                    )
                    self._add_finding(f)
                    return

    async def _check_log_exposure(self, assets: List[AssetInfo]) -> None:
        """Check for exposed log files."""
        log_paths = [
            '/logs/', '/log/', '/var/log/', '/debug.log',
            '/app.log', '/server.log', '/error.log',
            '/audit.log', '/access.log',
        ]
        for path in log_paths:
            url = urljoin(self.target.url, path)
            resp, _ = await self._request('GET', url)
            if resp and resp.status_code == 200:
                body = resp.text
                if re.search(r'\d{4}-\d{2}-\d{2}.*(?:ERROR|WARNING|INFO|DEBUG)', body):
                    f = (
                        FindingBuilder()
                        .name(f"Log File Exposed at {url}")
                        .category("A09")
                        .vuln_type("Log Exposure")
                        .severity(SeverityLevel.MEDIUM)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(url)
                        .cwe("CWE-532")
                        .description(
                            f"A log file is publicly accessible at {url}. "
                            "Log files may contain credentials, session tokens, IP addresses, "
                            "and internal system information."
                        )
                        .remediation(
                            "1. Move log files outside web root.\\n"
                            "2. Restrict access to log directories.\\n"
                            "3. Never log sensitive data (passwords, tokens, full credit card numbers)."
                        )
                        .detected_by("A09_LOG_EXPOSURE")
                        .build()
                    )
                    self._add_finding(f)

    async def _check_audit_trail(self) -> None:
        """Check for audit trail indicators in API responses."""
        resp, _ = await self._request('GET', self.target.url)
        if resp is None:
            return

        # Check for audit headers
        headers = {k.lower(): v for k, v in resp.headers.items()}
        has_request_id = any(k in headers for k in ['x-request-id', 'x-correlation-id', 'x-trace-id'])
        if not has_request_id:
            f = (
                FindingBuilder()
                .name("Missing Request Correlation ID / Audit Trail Header")
                .category("A09")
                .vuln_type("Missing Audit Trail")
                .severity(SeverityLevel.INFO)
                .confidence(ConfidenceLevel.MEDIUM)
                .url(self.target.url)
                .cwe("CWE-778")
                .description(
                    "No request correlation ID header (X-Request-ID, X-Correlation-ID) found. "
                    "Without correlation IDs, it's difficult to trace requests across distributed systems "
                    "and correlate security events during incident response."
                )
                .remediation(
                    "1. Generate unique request IDs for all incoming requests.\\n"
                    "2. Include X-Request-ID in all responses.\\n"
                    "3. Log request IDs alongside all events for traceability."
                )
                .detected_by("A09_AUDIT_TRAIL")
                .build()
            )
            self._add_finding(f)
