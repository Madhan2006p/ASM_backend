from __future__ import annotations
import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import httpx
from ..core import AssetInfo, BaseDetector, Finding, FindingBuilder, SeverityLevel, ConfidenceLevel

SENSITIVE_PATTERNS = {
    'password': r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'"<>&;,]+)',
    'api_key': r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{16,})',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    'jwt_token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'stripe_key': r'sk_(?:live|test)_[A-Za-z0-9]{24,}',
    'generic_secret': r'(?:secret|token|auth[_-]?token)\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{16,})',
    'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
}

WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ANON', 'ADH', 'AECDH', 'RC2']
WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1']

REQUIRED_SECURITY_HEADERS = {
    'strict-transport-security': {'desc': 'HSTS protects against SSL stripping', 'severity': SeverityLevel.MEDIUM, 'cwe': 'CWE-523', 'remediation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'},
    'content-security-policy': {'desc': 'CSP prevents XSS', 'severity': SeverityLevel.MEDIUM, 'cwe': 'CWE-693', 'remediation': "Content-Security-Policy: default-src 'self'"},
    'x-content-type-options': {'desc': 'Prevents MIME sniffing', 'severity': SeverityLevel.LOW, 'cwe': 'CWE-693', 'remediation': 'X-Content-Type-Options: nosniff'},
    'x-frame-options': {'desc': 'Prevents clickjacking', 'severity': SeverityLevel.MEDIUM, 'cwe': 'CWE-1021', 'remediation': 'X-Frame-Options: DENY'},
    'referrer-policy': {'desc': 'Controls referrer info', 'severity': SeverityLevel.LOW, 'cwe': 'CWE-200', 'remediation': 'Referrer-Policy: strict-origin-when-cross-origin'},
}


class CryptographicFailuresDetector(BaseDetector):
    owasp_category = 'A02'
    name = 'Cryptographic Failures'

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f'Starting A02 detection on {len(assets)} assets')
        tasks = [
            self._check_https_enforcement(),
            self._check_tls_config(),
            self._check_security_headers(),
            self._check_cookies(),
        ]
        for asset in assets[:30]:
            tasks.append(self._check_sensitive_data(asset))
        await asyncio.gather(*tasks, return_exceptions=True)
        self._log(f'A02 done. Found {len(self._findings)} issues.')
        return self._findings

    async def _check_https_enforcement(self) -> None:
        parsed = urlparse(self.target.url)
        if parsed.scheme == 'http':
            f = (FindingBuilder()
                .name('Application Served Over HTTP Without HTTPS')
                .category('A02').vuln_type('HTTP instead of HTTPS')
                .severity(SeverityLevel.HIGH).confidence(ConfidenceLevel.CERTAIN)
                .url(self.target.url).cwe('CWE-319').capec('CAPEC-94')
                .description('The application is served over unencrypted HTTP. All data including credentials is transmitted in cleartext.')
                .risk('All traffic including session cookies and credentials is in plaintext.')
                .impact('Complete confidentiality compromise of all data in transit.')
                .remediation('1. Deploy TLS certificate.\n2. Redirect all HTTP to HTTPS.\n3. Implement HSTS.')
                .add_ref('https://owasp.org/Top10/A02_2021-Cryptographic_Failures/')
                .evidence('Target URL uses HTTP scheme').detected_by('A02_HTTP_CHECK').build())
            self._add_finding(f)
        else:
            http_url = self.target.url.replace('https://', 'http://', 1)
            resp, elapsed = await self._request('GET', http_url)
            if resp and resp.status_code == 200 and str(resp.url).startswith('http://'):
                f = (FindingBuilder()
                    .name('HTTP Available Without Redirect to HTTPS')
                    .category('A02').vuln_type('HTTP instead of HTTPS')
                    .severity(SeverityLevel.HIGH).confidence(ConfidenceLevel.CERTAIN)
                    .url(http_url).cwe('CWE-319')
                    .description(f'HTTP version accessible at {http_url} without redirect to HTTPS.')
                    .risk('Clear-text channel available for interception.')
                    .remediation('Configure 301 redirect from HTTP to HTTPS.')
                    .request(self._build_request_obj('GET', http_url))
                    .response(self._build_response_obj(resp, elapsed))
                    .detected_by('A02_HTTP_CHECK').build())
                self._add_finding(f)

    async def _check_tls_config(self) -> None:
        parsed = urlparse(self.target.url)
        if parsed.scheme != 'https':
            return
        host = parsed.hostname
        port = parsed.port or 443
        try:
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(None, self._get_cert_info, host, port)
            if cert_info:
                await self._analyze_cert(cert_info, host, port)
        except Exception as e:
            self._log(f'TLS check error: {e}', 'DEBUG')

    def _get_cert_info(self, host: str, port: int) -> Optional[Dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return {'cert': ssock.getpeercert(), 'cipher': ssock.cipher(), 'version': ssock.version(), 'host': host, 'port': port}
        except Exception:
            return None

    async def _analyze_cert(self, cert_info: Dict, host: str, port: int) -> None:
        cert = cert_info.get('cert', {})
        cipher = cert_info.get('cipher', ('', '', 0))
        version = cert_info.get('version', '')
        not_after = cert.get('notAfter', '')
        if not_after:
            try:
                expire_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                days_left = (expire_dt - datetime.now(timezone.utc)).days
                if days_left < 0:
                    f = (FindingBuilder().name('Expired SSL/TLS Certificate').category('A02')
                        .vuln_type('Expired Certificates').severity(SeverityLevel.HIGH)
                        .confidence(ConfidenceLevel.CERTAIN).url(self.target.url).cwe('CWE-298')
                        .description(f'SSL cert for {host} expired on {not_after} ({abs(days_left)} days ago).')
                        .remediation('Renew SSL certificate immediately. Use Let\'s Encrypt for auto-renewal.')
                        .evidence(f'Certificate notAfter: {not_after}').detected_by('A02_CERT_CHECK').build())
                    self._add_finding(f)
                elif days_left < 30:
                    f = (FindingBuilder().name(f'SSL Certificate Expiring Soon ({days_left} days)').category('A02')
                        .vuln_type('Expired Certificates').severity(SeverityLevel.MEDIUM)
                        .confidence(ConfidenceLevel.CERTAIN).url(self.target.url).cwe('CWE-298')
                        .description(f'SSL cert for {host} expires in {days_left} days.')
                        .remediation('Renew SSL certificate before expiry.')
                        .detected_by('A02_CERT_CHECK').build())
                    self._add_finding(f)
            except Exception:
                pass
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        if subject == issuer:
            f = (FindingBuilder().name('Self-Signed SSL Certificate').category('A02')
                .vuln_type('Self-signed Certificates').severity(SeverityLevel.MEDIUM)
                .confidence(ConfidenceLevel.HIGH).url(self.target.url).cwe('CWE-295')
                .description(f'Self-signed certificate at {host}:{port}.')
                .remediation('Replace with certificate from trusted CA (e.g. Let\'s Encrypt).')
                .evidence(f'Subject equals Issuer: {subject.get("commonName", "Unknown")}')
                .detected_by('A02_CERT_CHECK').build())
            self._add_finding(f)
        cipher_name = cipher[0] if cipher else ''
        for weak in WEAK_CIPHERS:
            if weak in cipher_name.upper():
                f = (FindingBuilder().name(f'Weak Cipher Suite: {cipher_name}').category('A02')
                    .vuln_type('Weak Cipher Suites').severity(SeverityLevel.MEDIUM)
                    .confidence(ConfidenceLevel.HIGH).url(self.target.url).cwe('CWE-327')
                    .description(f'Weak cipher suite {cipher_name} negotiated.')
                    .remediation('Allow only AES-GCM and ChaCha20-Poly1305 cipher suites.')
                    .evidence(f'Negotiated: {cipher_name} over {version}')
                    .detected_by('A02_CIPHER_CHECK').build())
                self._add_finding(f)
                break

    async def _check_security_headers(self) -> None:
        resp, elapsed = await self._request('GET', self.target.url)
        if resp is None:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header_name, info in REQUIRED_SECURITY_HEADERS.items():
            if self.target.url.startswith('http://') and header_name == 'strict-transport-security':
                continue
            if header_name not in headers:
                f = (FindingBuilder().name(f'Missing Security Header: {header_name}')
                    .category('A02').vuln_type('Missing HSTS' if 'hsts' in header_name or 'transport' in header_name else 'Weak Cookie Flags')
                    .severity(info['severity']).confidence(ConfidenceLevel.CERTAIN)
                    .url(self.target.url).cwe(info['cwe'])
                    .description(info['desc'])
                    .remediation(info['remediation'])
                    .evidence(f'Header {header_name} not in response')
                    .detected_by('A02_HEADER_CHECK').build())
                self._add_finding(f)

    async def _check_cookies(self) -> None:
        resp, elapsed = await self._request('GET', self.target.url)
        if resp is None:
            return
        raw_set_cookie = '\n'.join([v for k, v in resp.headers.items() if k.lower() == 'set-cookie'])
        for line in raw_set_cookie.split('\n'):
            if not line.strip():
                continue
            name = line.split('=')[0].strip()
            line_lower = line.lower()
            is_session = any(kw in name.lower() for kw in ['session', 'sess', 'token', 'auth', 'jwt'])
            if 'https' in self.target.url and 'secure' not in line_lower:
                f = (FindingBuilder().name(f"Cookie '{name}' Missing Secure Flag")
                    .category('A02').vuln_type('Weak Cookie Flags')
                    .severity(SeverityLevel.MEDIUM if is_session else SeverityLevel.LOW)
                    .confidence(ConfidenceLevel.CERTAIN).url(self.target.url).cwe('CWE-614')
                    .description(f"Cookie '{name}' missing Secure flag, transmittable over HTTP.")
                    .remediation(f"Add Secure flag: Set-Cookie: {name}=...; Secure; HttpOnly")
                    .evidence(f'Set-Cookie: {line[:200]}')
                    .detected_by('A02_COOKIE_CHECK').build())
                self._add_finding(f)
            if 'httponly' not in line_lower and is_session:
                f = (FindingBuilder().name(f"Session Cookie '{name}' Missing HttpOnly Flag")
                    .category('A02').vuln_type('Weak Cookie Flags')
                    .severity(SeverityLevel.MEDIUM).confidence(ConfidenceLevel.CERTAIN)
                    .url(self.target.url).cwe('CWE-1004')
                    .description(f"Session cookie '{name}' accessible via JavaScript (no HttpOnly).")
                    .remediation(f"Add HttpOnly: Set-Cookie: {name}=...; HttpOnly")
                    .detected_by('A02_COOKIE_CHECK').build())
                self._add_finding(f)

    async def _check_sensitive_data(self, asset: AssetInfo) -> None:
        resp, elapsed = await self._request('GET', asset.url)
        if resp is None:
            return
        ct = resp.headers.get('content-type', '').lower()
        if not any(t in ct for t in ['text/', 'application/json', 'javascript']):
            return
        body = resp.text
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                severity = (SeverityLevel.CRITICAL if pattern_name in ('private_key', 'stripe_key')
                           else SeverityLevel.HIGH if pattern_name in ('password', 'api_key', 'jwt_token')
                           else SeverityLevel.MEDIUM)
                f = (FindingBuilder()
                    .name(f'Sensitive Data Exposure: {pattern_name.replace("_", " ").title()}')
                    .category('A02').vuln_type('Sensitive Data in Response')
                    .severity(severity).confidence(ConfidenceLevel.HIGH)
                    .url(asset.url).cwe('CWE-312').capec('CAPEC-150')
                    .description(f'{pattern_name} pattern found in response from {asset.url}.')
                    .risk('Exposed secrets can be used by attackers immediately.')
                    .impact('Account compromise, unauthorized API access, data breach.')
                    .remediation(f'Remove {pattern_name} from responses. Rotate exposed credentials immediately.')
                    .evidence(f'Pattern {pattern_name} matched in response body')
                    .detected_by('A02_SENSITIVE_DATA').build())
                self._add_finding(f)
                break
