"""
A06 - Vulnerable and Outdated Components Detector
==================================================
Detects:
- Server/framework version disclosure
- Known vulnerable component versions
- Outdated CMS (WordPress, Drupal, Joomla)
- Outdated JavaScript libraries
- CVE matching against detected versions
- Components with known exploits
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
from ..cve_mapper.nvd_client import CVEMapper, build_cpe, KNOWN_VULNERABLE_VERSIONS


# ─── Technology version patterns (headers, body) ─────────────────────────────

TECH_HEADER_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
    'server': [
        (r'Apache/([0-9.]+)', 'apache'),
        (r'nginx/([0-9.]+)', 'nginx'),
        (r'Microsoft-IIS/([0-9.]+)', 'iis'),
        (r'lighttpd/([0-9.]+)', 'lighttpd'),
        (r'Jetty/([0-9.]+)', 'jetty'),
        (r'Tomcat/([0-9.]+)', 'tomcat'),
        (r'PHP/([0-9.]+)', 'php'),
        (r'OpenSSL/([0-9.]+)', 'openssl'),
    ],
    'x-powered-by': [
        (r'PHP/([0-9.]+)', 'php'),
        (r'ASP\.NET', 'aspnet'),
        (r'Express/([0-9.]+)', 'express'),
        (r'Servlet/([0-9.]+)', 'servlet'),
        (r'JBoss/([0-9.]+)', 'jboss'),
    ],
    'x-aspnet-version': [
        (r'([0-9.]+)', 'aspnet'),
    ],
    'x-generator': [
        (r'WordPress ([0-9.]+)', 'wordpress'),
        (r'Drupal ([0-9.]+)', 'drupal'),
        (r'Joomla! ([0-9.]+)', 'joomla'),
    ],
}

# Body-based technology detection
TECH_BODY_PATTERNS = [
    (r'wp-content/themes', 'wordpress', None),
    (r'var\s+Drupal\s*=\s*\{', 'drupal', None),
    (r'Joomla!\s+([0-9.]+)', 'joomla', r'([0-9.]+)'),
    (r'Powered by <a[^>]*>WordPress</a>', 'wordpress', None),
    (r'<meta name="generator" content="WordPress ([0-9.]+)"', 'wordpress', r'([0-9.]+)'),
    (r'<meta name="generator" content="Drupal ([0-9.]+)"', 'drupal', r'([0-9.]+)'),
    (r'jQuery v([0-9.]+)', 'jquery', r'([0-9.]+)'),
    (r'jquery/([0-9.]+)/jquery\.min\.js', 'jquery', r'([0-9.]+)'),
    (r'bootstrap/([0-9.]+)/', 'bootstrap', r'([0-9.]+)'),
    (r'angular(?:js)?/([0-9.]+)/', 'angular', r'([0-9.]+)'),
    (r'react@([0-9.]+)', 'react', r'([0-9.]+)'),
    (r'vue@([0-9.]+)', 'vue', r'([0-9.]+)'),
    (r'lodash@([0-9.]+)', 'lodash', r'([0-9.]+)'),
    (r'moment\.js\s*v?([0-9.]+)', 'momentjs', r'([0-9.]+)'),
]

# Known vulnerable versions (offline check - fast)
KNOWN_VULN_VERSIONS: Dict[str, List[Dict]] = {
    **KNOWN_VULNERABLE_VERSIONS,
    'jquery': [
        {'max_version': '1.12.4', 'cve': 'CVE-2019-11358', 'cvss': 6.1, 'desc': 'jQuery prototype pollution'},
        {'max_version': '2.2.4', 'cve': 'CVE-2019-11358', 'cvss': 6.1, 'desc': 'jQuery prototype pollution'},
        {'max_version': '3.4.0', 'cve': 'CVE-2019-11358', 'cvss': 6.1, 'desc': 'jQuery prototype pollution'},
        {'max_version': '3.5.0', 'cve': 'CVE-2020-11022', 'cvss': 6.9, 'desc': 'jQuery XSS in HTML manipulation'},
    ],
    'bootstrap': [
        {'max_version': '3.4.0', 'cve': 'CVE-2018-14041', 'cvss': 6.1, 'desc': 'Bootstrap XSS in tooltip/popover'},
        {'max_version': '4.3.0', 'cve': 'CVE-2019-8331', 'cvss': 6.1, 'desc': 'Bootstrap XSS via data-template'},
    ],
    'angular': [
        {'max_version': '1.7.9', 'cve': 'CVE-2023-26118', 'cvss': 7.4, 'desc': 'AngularJS ReDoS'},
    ],
    'lodash': [
        {'max_version': '4.17.15', 'cve': 'CVE-2021-23337', 'cvss': 7.2, 'desc': 'Lodash command injection via template'},
        {'max_version': '4.17.19', 'cve': 'CVE-2020-8203', 'cvss': 7.4, 'desc': 'Lodash prototype pollution'},
    ],
}

# WordPress plugin vuln check paths
WP_PLUGIN_PATHS = [
    '/wp-content/plugins/akismet/readme.txt',
    '/wp-content/plugins/jetpack/readme.txt',
    '/wp-content/plugins/contact-form-7/readme.txt',
    '/wp-content/plugins/woocommerce/readme.txt',
]

# Drupal-specific version check
DRUPAL_CHANGELOG_PATH = '/CHANGELOG.txt'
DRUPAL_CORE_PATH = '/core/CHANGELOG.txt'


def _version_less_than(version: str, max_version: str) -> bool:
    """Compare semantic version strings."""
    try:
        v1 = tuple(int(x) for x in version.split('.')[:3])
        v2 = tuple(int(x) for x in max_version.split('.')[:3])
        return v1 <= v2
    except (ValueError, AttributeError):
        return False


class OutdatedComponentsDetector(BaseDetector):
    """
    A06:2021 - Vulnerable and Outdated Components Detector.
    Fingerprints technologies and cross-references versions against
    known CVEs and vulnerability databases.
    """
    owasp_category = "A06"
    name = "Vulnerable and Outdated Components"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cve_mapper = CVEMapper(self.config)

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A06 detection on {len(assets)} assets")

        # Collect tech fingerprints
        detected: Dict[str, Optional[str]] = {}  # {product: version}

        tasks = [
            self._fingerprint_headers(detected),
            self._fingerprint_body(assets, detected),
            self._check_wordpress(detected),
            self._check_drupal(detected),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Check detected versions against vulnerability DB
        await self._check_known_vulns(detected)

        self._log(f"A06 detection complete. Found {len(self._findings)} issues.")
        return self._findings

    async def _fingerprint_headers(self, detected: Dict) -> None:
        """Fingerprint tech from HTTP response headers."""
        resp, _ = await self._request('GET', self.target.url)
        if resp is None:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header_name, patterns in TECH_HEADER_PATTERNS.items():
            header_val = headers.get(header_name, '')
            if not header_val:
                continue
            for pattern, product in patterns:
                m = re.search(pattern, header_val, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else None
                    if product not in detected:
                        detected[product] = version
                    self._log(f"Detected: {product} {version or '(unknown version)'} via {header_name} header")

    async def _fingerprint_body(self, assets: List[AssetInfo], detected: Dict) -> None:
        """Fingerprint technologies from HTML/JS body."""
        resp, _ = await self._request('GET', self.target.url)
        if resp is None:
            return

        body = resp.text
        for pattern, product, ver_group in TECH_BODY_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                version = None
                if ver_group:
                    vm = re.search(ver_group, m.group(0))
                    if vm:
                        version = vm.group(1)
                if product not in detected:
                    detected[product] = version
                    self._log(f"Detected: {product} {version or '(unknown version)'} via body pattern")

        # Also scan JS files for library versions
        js_assets = [a for a in assets if a.asset_type == 'JS_FILE']
        for js_asset in js_assets[:10]:
            js_resp, _ = await self._request('GET', js_asset.url)
            if js_resp is None:
                continue
            js_body = js_resp.text[:50000]  # First 50KB
            for pattern, product, ver_group in TECH_BODY_PATTERNS:
                if product in detected:
                    continue
                m = re.search(pattern, js_body, re.IGNORECASE)
                if m and ver_group:
                    vm = re.search(ver_group, m.group(0))
                    if vm:
                        detected[product] = vm.group(1)

    async def _check_wordpress(self, detected: Dict) -> None:
        """WordPress-specific version checks."""
        if 'wordpress' not in detected:
            return

        # Check wp-login.php for version leaks
        for path in ['/readme.html', '/license.txt', '/wp-includes/version.php']:
            url = urljoin(self.target.url, path)
            resp, _ = await self._request('GET', url)
            if resp and resp.status_code == 200:
                m = re.search(r'Version ([0-9.]+)', resp.text, re.IGNORECASE)
                if m and not detected.get('wordpress'):
                    detected['wordpress'] = m.group(1)
                    break

        # Check wp-json for version info
        wp_api = urljoin(self.target.url, '/wp-json/')
        resp, _ = await self._request('GET', wp_api)
        if resp and resp.status_code == 200:
            try:
                import json
                data = resp.json()
                version = data.get('generator', '').replace('https://wordpress.org/?v=', '')
                if version and version != data.get('generator', ''):
                    detected['wordpress'] = version
            except Exception:
                pass

    async def _check_drupal(self, detected: Dict) -> None:
        """Drupal-specific version detection."""
        for path in [DRUPAL_CHANGELOG_PATH, DRUPAL_CORE_PATH, '/core/package.json']:
            url = urljoin(self.target.url, path)
            resp, _ = await self._request('GET', url)
            if resp and resp.status_code == 200:
                m = re.search(r'Drupal\s+([0-9.]+)', resp.text, re.IGNORECASE)
                if m:
                    detected['drupal'] = m.group(1)
                    break

    async def _check_known_vulns(self, detected: Dict) -> None:
        """Cross-reference detected components with vulnerability database."""
        for product, version in detected.items():
            self._log(f"Checking vulnerabilities for {product} {version or 'unknown'}")

            # First try offline lookup
            if product.lower() in KNOWN_VULN_VERSIONS:
                vulns = KNOWN_VULN_VERSIONS[product.lower()]
                for vuln in vulns:
                    max_ver = vuln.get('max_version', '9999.9.9')
                    if version and _version_less_than(version, max_ver):
                        await self._report_component_vuln(
                            product, version,
                            vuln.get('cve', ''),
                            vuln.get('cvss', 7.0),
                            vuln.get('desc', f'Known vulnerability in {product} <= {max_ver}'),
                            [vuln.get('cve', '')]
                        )

            # Try CVE mapper for online lookup if version known
            if version and len(version) > 1:
                try:
                    cve_ids = await self.cve_mapper.search_by_keyword(f"{product} {version}")
                    if cve_ids:
                        # Only report if we find high-severity CVEs
                        for cve_id in cve_ids[:3]:
                            cve_data = await self.cve_mapper.get_cve(cve_id)
                            if cve_data and (cve_data.get('cvss_score') or 0) >= 7.0:
                                await self._report_component_vuln(
                                    product, version,
                                    cve_id,
                                    cve_data.get('cvss_score', 7.0),
                                    cve_data.get('description', f'{product} {version} - {cve_id}'),
                                    [cve_id]
                                )
                                break
                except Exception:
                    pass

    async def _report_component_vuln(
        self,
        product: str,
        version: Optional[str],
        cve_id: str,
        cvss_score: float,
        description: str,
        cve_list: List[str],
    ) -> None:
        """Create a finding for a vulnerable component."""
        version_str = version or 'Unknown'
        severity = SeverityLevel.from_cvss(cvss_score)

        f = (
            FindingBuilder()
            .name(f"Vulnerable Component: {product.title()} {version_str} ({cve_id})" if cve_id
                  else f"Outdated Component: {product.title()} {version_str}")
            .category("A06")
            .vuln_type("Vulnerable Component")
            .severity(severity)
            .confidence(ConfidenceLevel.HIGH if version else ConfidenceLevel.MEDIUM)
            .url(self.target.url)
            .cwe("CWE-1104")
            .capec("CAPEC-310")
            .description(
                f"The application appears to use {product.title()} version {version_str}. "
                f"{description}"
            )
            .risk(
                f"Known vulnerabilities exist in {product.title()} {version_str}. "
                "Attackers can exploit public proof-of-concept exploits against this version."
            )
            .impact(
                "Depends on specific vulnerability: may include RCE, data breach, "
                "authentication bypass, or denial of service."
            )
            .remediation(
                f"1. Update {product.title()} to the latest stable release.\\n"
                "2. Monitor security advisories for all components.\\n"
                "3. Implement Software Composition Analysis (SCA) in the CI/CD pipeline.\\n"
                "4. Subscribe to NVD alerts for components used in production."
            )
            .add_ref(f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else
                     "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/")
            .add_ref("https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/")
            .cves(cve_list)
            .cvss(cvss_score)
            .evidence(f"Detected {product.title()} version {version_str} via fingerprinting")
            .proof(f"Component: {product} | Version: {version_str} | CVE: {cve_id}")
            .detected_by("A06_COMPONENT_CHECK")
            .build()
        )
        self._add_finding(f)
