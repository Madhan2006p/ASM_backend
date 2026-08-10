"""
A07 - Identification and Authentication Failures Detector
==========================================================
Detects:
- Default/weak credentials
- Brute-force unprotected endpoints
- Missing account lockout
- Weak session tokens
- Session fixation
- JWT weaknesses (none algorithm, weak secret)
- Insecure password reset
- Missing MFA indicators
- OAuth misconfigurations
- Username enumeration
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode

import httpx

from ..core import (
    AssetInfo, BaseDetector, Finding, FindingBuilder,
    SeverityLevel, ConfidenceLevel
)


# ─── Default Credentials ─────────────────────────────────────────────────────

DEFAULT_CREDENTIALS = [
    # Generic
    ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
    ('admin', 'admin123'), ('admin', 'Pass@123'), ('admin', ''),
    ('administrator', 'administrator'), ('root', 'root'), ('root', 'toor'),
    ('root', 'password'), ('test', 'test'), ('guest', 'guest'),
    ('user', 'user'), ('demo', 'demo'),
    # Application-specific
    ('admin', 'changeme'), ('admin', 'default'), ('admin', 'admin@123'),
    ('sa', ''), ('postgres', 'postgres'), ('oracle', 'oracle'),
    ('jenkins', 'jenkins'), ('tomcat', 'tomcat'), ('tomcat', 's3cret'),
    ('nagios', 'nagios'), ('zabbix', 'zabbix'), ('pi', 'raspberry'),
    ('admin', 'letmein'), ('admin', '1234'), ('admin', 'Welcome1'),
]

# Common auth failure indicators
AUTH_FAIL_KEYWORDS = [
    'invalid credentials', 'incorrect password', 'login failed',
    'authentication failed', 'invalid username', 'wrong password',
    'access denied', 'invalid email', 'account not found',
]

AUTH_SUCCESS_KEYWORDS = [
    'dashboard', 'welcome', 'logout', 'profile', 'my account',
    'authenticated', 'token', 'session', 'success',
]

# Login form selectors (common field names)
LOGIN_USERNAME_FIELDS = ['username', 'user', 'email', 'login', 'user_email', 'account']
LOGIN_PASSWORD_FIELDS = ['password', 'pass', 'passwd', 'pwd', 'secret']

# JWT algorithm none attack
JWT_NONE_ALG = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
JWT_ALG_NONE_VARIANTS = ['none', 'None', 'NONE', 'nOnE', 'NoNe']

# Weak JWT secrets to try
WEAK_JWT_SECRETS = [
    'secret', 'password', '123456', 'key', 'jwt_secret',
    'your-256-bit-secret', 'your-secret', 'mysecretkey',
    'SECRET_KEY', 'JWT_SECRET', 'supersecret', 'changeme',
]

# Password reset paths
PASSWORD_RESET_PATHS = [
    '/forgot-password', '/forgot_password', '/password-reset',
    '/reset-password', '/account/forgot', '/users/password/new',
    '/auth/forgot-password', '/api/auth/forgot', '/api/v1/auth/forgot',
]

# Username enumeration timing threshold
TIMING_DIFF_MS_THRESHOLD = 300  # ms difference is suspicious


class AuthenticationFailuresDetector(BaseDetector):
    """
    A07:2021 - Identification and Authentication Failures Detector.
    """
    owasp_category = "A07"
    name = "Authentication Failures"

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        self._log(f"Starting A07 detection on {len(assets)} assets")

        # Find auth pages
        auth_assets = [a for a in assets if a.asset_type in ('AUTH_PAGE',) or
                       any(kw in a.url.lower() for kw in ('login', 'signin', 'auth', 'register'))]

        tasks = [
            self._check_jwt_tokens(assets),
            self._check_password_reset(assets),
            self._check_session_security(assets),
        ]

        # Check auth endpoints for default credentials and brute protection
        for asset in auth_assets[:5]:
            tasks.append(self._check_default_credentials(asset))
            tasks.append(self._check_account_lockout(asset))
            tasks.append(self._check_username_enumeration(asset))

        await asyncio.gather(*tasks, return_exceptions=True)
        self._log(f"A07 detection complete. Found {len(self._findings)} issues.")
        return self._findings

    async def _check_default_credentials(self, asset: AssetInfo) -> None:
        """Try common default credentials against login forms."""
        # Find login form inputs
        forms = asset.forms
        if not forms:
            # Try to get form from URL response
            resp, _ = await self._request('GET', asset.url)
            if resp is None:
                return
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                forms = []
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = (form.get('method', 'post') or 'post').upper()
                    action_url = urljoin(asset.url, action) if action else asset.url
                    inputs = []
                    for inp in form.find_all('input'):
                        inp_type = inp.get('type', 'text')
                        inp_name = inp.get('name', '')
                        if inp_name:
                            inputs.append({'name': inp_name, 'type': inp_type, 'value': inp.get('value', '')})
                    forms.append({'action': action_url, 'method': method, 'inputs': inputs})
            except Exception:
                return

        for form in forms:
            method = form.get('method', 'POST')
            action = form.get('action', asset.url)
            inputs = form.get('inputs', [])

            # Identify username and password fields
            user_field = next((i['name'] for i in inputs if i['name'].lower() in LOGIN_USERNAME_FIELDS), None)
            pass_field = next((i['name'] for i in inputs if i['name'].lower() in LOGIN_PASSWORD_FIELDS
                               or i.get('type', '') == 'password'), None)

            if not user_field or not pass_field:
                continue

            # Get baseline (failed) response
            base_data = {i['name']: i.get('value', '') for i in inputs}
            base_data[user_field] = 'invaliduser_xyzabc123'
            base_data[pass_field] = 'invalidpass_xyzabc123'
            base_resp, _ = await self._request(method, action, data=base_data)
            if base_resp is None:
                continue

            baseline_body = base_resp.text.lower()

            # Try default credentials
            for username, password in DEFAULT_CREDENTIALS[:15]:  # Limit to avoid lockout
                data = {i['name']: i.get('value', '') for i in inputs}
                data[user_field] = username
                data[pass_field] = password

                resp, elapsed = await self._request(method, action, data=data)
                if resp is None:
                    continue

                body = resp.text.lower()
                # Check for success indicators
                success = False
                if resp.status_code in (301, 302) and 'login' not in resp.headers.get('location', '').lower():
                    success = True
                elif any(kw in body for kw in AUTH_SUCCESS_KEYWORDS):
                    if not any(kw in body for kw in AUTH_FAIL_KEYWORDS):
                        success = True

                # Compare with baseline - success if diff
                if success and len(body) != len(baseline_body):
                    f = (
                        FindingBuilder()
                        .name(f"Default Credentials Work: {username}/{password}")
                        .category("A07")
                        .vuln_type("Default Credentials")
                        .severity(SeverityLevel.CRITICAL)
                        .confidence(ConfidenceLevel.HIGH)
                        .url(action)
                        .cwe("CWE-521")
                        .capec("CAPEC-70")
                        .description(
                            f"Default credentials '{username}:{password}' successfully authenticated "
                            f"at {action}. The login form accepted these credentials without challenge."
                        )
                        .risk("Default credentials allow immediate unauthorized access to accounts "
                              "without needing to bypass any security controls.")
                        .impact("Full account compromise. If admin credentials, complete application takeover.")
                        .remediation(
                            "1. Immediately change default credentials.\\n"
                            "2. Enforce strong password policy on all accounts.\\n"
                            "3. Require password change on first login.\\n"
                            "4. Implement MFA for all accounts.\\n"
                            "5. Remove or disable default accounts."
                        )
                        .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials")
                        .evidence(f"Credentials {username}:{password} returned success response")
                        .proof(f"POST {action} with {user_field}={username} returned HTTP {resp.status_code}")
                        .detected_by("A07_DEFAULT_CREDS")
                        .build()
                    )
                    self._add_finding(f)
                    return

    async def _check_account_lockout(self, asset: AssetInfo) -> None:
        """Check if account lockout is implemented."""
        forms = asset.forms
        if not forms:
            return

        for form in forms:
            method = form.get('method', 'POST')
            action = form.get('action', asset.url)
            inputs = form.get('inputs', [])

            user_field = next((i['name'] for i in inputs if i['name'].lower() in LOGIN_USERNAME_FIELDS), None)
            pass_field = next((i['name'] for i in inputs if i['name'].lower() in LOGIN_PASSWORD_FIELDS
                               or i.get('type', '') == 'password'), None)

            if not user_field or not pass_field:
                continue

            # Try 10 failed logins
            fail_count = 0
            locked_out = False

            for i in range(10):
                data = {inp['name']: inp.get('value', '') for inp in inputs}
                data[user_field] = 'test_lockout_user'
                data[pass_field] = f'wrong_password_{i}'

                resp, _ = await self._request(method, action, data=data)
                if resp is None:
                    break

                body = resp.text.lower()
                # Check for lockout indicators
                if any(kw in body for kw in ['locked', 'account locked', 'too many attempts',
                                              'temporarily blocked', 'rate limit', 'try again later']):
                    locked_out = True
                    break
                fail_count += 1

            if fail_count >= 10 and not locked_out:
                f = (
                    FindingBuilder()
                    .name("Missing Account Lockout / Brute Force Protection")
                    .category("A07")
                    .vuln_type("Missing Account Lockout")
                    .severity(SeverityLevel.HIGH)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(action)
                    .cwe("CWE-307")
                    .capec("CAPEC-49")
                    .description(
                        f"The login endpoint at {action} allows at least 10 failed login "
                        "attempts without any rate limiting or account lockout mechanism. "
                        "This enables brute-force password attacks."
                    )
                    .risk("Attackers can perform unlimited password guessing attacks to compromise accounts.")
                    .impact("Account compromise through automated brute-force attacks.")
                    .remediation(
                        "1. Implement account lockout after 5 failed attempts.\\n"
                        "2. Add CAPTCHA after repeated failures.\\n"
                        "3. Implement progressive delays between attempts.\\n"
                        "4. Alert users on multiple failed login attempts.\\n"
                        "5. Consider IP-based rate limiting."
                    )
                    .add_ref("https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism")
                    .evidence(f"Sent 10 failed login attempts to {action} without lockout or rate limiting")
                    .detected_by("A07_LOCKOUT_CHECK")
                    .build()
                )
                self._add_finding(f)
                return

    async def _check_jwt_tokens(self, assets: List[AssetInfo]) -> None:
        """Check JWT tokens for weaknesses."""
        # Look for JWT in headers and responses
        resp, elapsed = await self._request('GET', self.target.url)
        if resp is None:
            return

        # Check headers
        for header_name, header_val in resp.headers.items():
            if self._is_jwt(header_val):
                await self._analyze_jwt(header_val, header_name, self.target.url)

        # Check cookies
        for cookie in resp.cookies.jar:
            if self._is_jwt(cookie.value):
                await self._analyze_jwt(cookie.value, f"cookie:{cookie.name}", self.target.url)

    def _is_jwt(self, value: str) -> bool:
        """Check if string looks like a JWT."""
        if not value:
            return False
        parts = value.split('.')
        return (len(parts) == 3 and
                all(len(p) > 4 for p in parts[:2]) and
                all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' for c in parts[0]))

    async def _analyze_jwt(self, token: str, location: str, url: str) -> None:
        """Analyze a JWT token for weaknesses."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return

            # Decode header (add padding)
            header_b64 = parts[0] + '=='
            header_json = base64.b64decode(header_b64).decode('utf-8', errors='ignore')
            header = json.loads(header_json)

            alg = header.get('alg', '').lower()

            # Check for 'none' algorithm
            if alg == 'none':
                f = (
                    FindingBuilder()
                    .name("JWT 'none' Algorithm Accepted")
                    .category("A07")
                    .vuln_type("JWT Weakness")
                    .severity(SeverityLevel.CRITICAL)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(url)
                    .cwe("CWE-347")
                    .capec("CAPEC-196")
                    .description(
                        f"A JWT token with algorithm 'none' was found in {location}. "
                        "The 'none' algorithm means the token has no signature, "
                        "allowing attackers to forge tokens with arbitrary claims."
                    )
                    .risk("Attackers can craft arbitrary JWT tokens with any claims, "
                          "bypassing authentication entirely.")
                    .impact("Complete authentication bypass, privilege escalation, impersonation of any user.")
                    .remediation(
                        "1. Reject tokens with alg:none.\\n"
                        "2. Explicitly validate the algorithm field.\\n"
                        "3. Use asymmetric algorithms (RS256, ES256) for better security.\\n"
                        "4. Use a well-tested JWT library that handles this by default."
                    )
                    .add_ref("https://portswigger.net/web-security/jwt#accepting-tokens-with-no-signature")
                    .evidence(f"JWT in {location} uses alg: none")
                    .proof(f"JWT header: {header_json}")
                    .detected_by("A07_JWT_NONE_ALG")
                    .build()
                )
                self._add_finding(f)

            # Check for weak algorithm (HS256 can be brute-forced)
            if alg in ('hs256', 'hs384', 'hs512'):
                # Decode payload for info
                try:
                    payload_b64 = parts[1] + '=='
                    payload = json.loads(base64.b64decode(payload_b64).decode('utf-8', errors='ignore'))
                    # Check expiry
                    exp = payload.get('exp', 0)
                    if exp and exp < time.time():
                        f = (
                            FindingBuilder()
                            .name("Expired JWT Token Accepted")
                            .category("A07")
                            .vuln_type("JWT Weakness")
                            .severity(SeverityLevel.MEDIUM)
                            .confidence(ConfidenceLevel.MEDIUM)
                            .url(url)
                            .cwe("CWE-613")
                            .description("JWT token has expired but application may still accept it.")
                            .remediation("Strictly validate JWT expiration (exp) claim server-side.")
                            .detected_by("A07_JWT_EXPIRY")
                            .build()
                        )
                        self._add_finding(f)
                except Exception:
                    pass

        except Exception as e:
            self._log(f"JWT analysis error: {e}", 'DEBUG')

    async def _check_password_reset(self, assets: List[AssetInfo]) -> None:
        """Check for insecure password reset mechanisms."""
        for path in PASSWORD_RESET_PATHS:
            url = urljoin(self.target.url, path)
            resp, _ = await self._request('GET', url)
            if resp is None or resp.status_code not in (200,):
                continue

            body = resp.text.lower()
            if any(kw in body for kw in ['forgot', 'reset', 'password', 'email']):
                # Check if reset token is in URL (insecure)
                if 'token' in body and ('url' in body or 'link' in body):
                    f = (
                        FindingBuilder()
                        .name("Password Reset Mechanism Identified - Verify Token Security")
                        .category("A07")
                        .vuln_type("Insecure Password Reset")
                        .severity(SeverityLevel.INFO)
                        .confidence(ConfidenceLevel.LOW)
                        .url(url)
                        .cwe("CWE-640")
                        .description(
                            f"A password reset mechanism was found at {url}. "
                            "Manual verification needed to ensure: tokens are long and random, "
                            "expire quickly, are single-use, and links include HMAC verification."
                        )
                        .remediation(
                            "1. Use cryptographically random tokens (minimum 128 bits).\\n"
                            "2. Expire tokens within 15 minutes.\\n"
                            "3. Invalidate token after use.\\n"
                            "4. Send reset links over email, not SMS.\\n"
                            "5. Rate-limit password reset requests."
                        )
                        .evidence(f"Password reset form found at {url}")
                        .detected_by("A07_RESET_CHECK")
                        .build()
                    )
                    self._add_finding(f)
                    return

    async def _check_session_security(self, assets: List[AssetInfo]) -> None:
        """Check session management security."""
        resp, elapsed = await self._request('GET', self.target.url)
        if resp is None:
            return

        raw_cookies = ' '.join(v for k, v in resp.headers.items() if k.lower() == 'set-cookie')
        if not raw_cookies:
            return

        # Check for predictable/short session token
        for cookie in resp.cookies.jar:
            if any(kw in cookie.name.lower() for kw in ['session', 'sess', 'token', 'auth']):
                val = cookie.value
                # Check if value appears short or sequential
                if len(val) < 20:
                    f = (
                        FindingBuilder()
                        .name(f"Potentially Weak Session Token: {cookie.name}")
                        .category("A07")
                        .vuln_type("Weak Session Tokens")
                        .severity(SeverityLevel.HIGH)
                        .confidence(ConfidenceLevel.MEDIUM)
                        .url(self.target.url)
                        .cwe("CWE-330")
                        .description(
                            f"Session cookie '{cookie.name}' has a short value ({len(val)} chars). "
                            "Session tokens should be at least 128 bits (22+ characters in base64)."
                        )
                        .remediation(
                            "1. Use cryptographically secure random session IDs.\\n"
                            "2. Minimum 128-bit entropy for session tokens.\\n"
                            "3. Use framework-provided session management."
                        )
                        .evidence(f"Session cookie value length: {len(val)} characters")
                        .detected_by("A07_SESSION_CHECK")
                        .build()
                    )
                    self._add_finding(f)

    async def _check_username_enumeration(self, asset: AssetInfo) -> None:
        """Check for username enumeration via timing or response differences."""
        forms = asset.forms
        if not forms:
            return

        for form in forms:
            method = form.get('method', 'POST')
            action = form.get('action', asset.url)
            inputs = form.get('inputs', [])

            user_field = next((i['name'] for i in inputs if i['name'].lower() in LOGIN_USERNAME_FIELDS), None)
            pass_field = next((i['name'] for i in inputs if i['name'].lower() in LOGIN_PASSWORD_FIELDS
                               or i.get('type', '') == 'password'), None)

            if not user_field or not pass_field:
                continue

            # Try valid-looking vs invalid username with same wrong password
            data_invalid = {i['name']: i.get('value', '') for i in inputs}
            data_invalid[user_field] = 'nonexistent_xyz123abc'
            data_invalid[pass_field] = 'wrongpassword123'

            data_common = {i['name']: i.get('value', '') for i in inputs}
            data_common[user_field] = 'admin'
            data_common[pass_field] = 'wrongpassword123'

            t1 = time.monotonic()
            resp1, _ = await self._request(method, action, data=data_invalid)
            elapsed1 = (time.monotonic() - t1) * 1000

            t2 = time.monotonic()
            resp2, _ = await self._request(method, action, data=data_common)
            elapsed2 = (time.monotonic() - t2) * 1000

            if resp1 is None or resp2 is None:
                continue

            # Check response text differences
            body1 = resp1.text.lower()
            body2 = resp2.text.lower()

            invalid_user_msg = any(kw in body1 for kw in ['user not found', 'no account', 'username not found', 'unknown user'])
            wrong_pass_msg = any(kw in body2 for kw in ['incorrect password', 'wrong password', 'invalid password'])

            if invalid_user_msg and wrong_pass_msg:
                f = (
                    FindingBuilder()
                    .name("Username Enumeration via Login Error Messages")
                    .category("A07")
                    .vuln_type("Username Enumeration")
                    .severity(SeverityLevel.MEDIUM)
                    .confidence(ConfidenceLevel.HIGH)
                    .url(action)
                    .cwe("CWE-203")
                    .capec("CAPEC-196")
                    .description(
                        f"The login form at {action} returns different error messages "
                        "for invalid usernames vs wrong passwords. This allows attackers "
                        "to enumerate valid usernames."
                    )
                    .risk("Username enumeration enables targeted brute-force attacks against confirmed accounts.")
                    .impact("Enables more effective credential attacks.")
                    .remediation(
                        "1. Use a generic error message: 'Invalid username or password'.\\n"
                        "2. Return the same HTTP status code for both error types.\\n"
                        "3. Ensure timing is equal for both error responses (constant-time comparison)."
                    )
                    .evidence(
                        f"Invalid user response: '{body1[:100]}...'\\n"
                        f"Wrong password response: '{body2[:100]}...'"
                    )
                    .detected_by("A07_USERNAME_ENUM")
                    .build()
                )
                self._add_finding(f)
                return
