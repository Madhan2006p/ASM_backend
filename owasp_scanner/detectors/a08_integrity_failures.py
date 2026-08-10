"""A08:2021 – Software and Data Integrity Failures detector.

Detects:
- Loaded scripts without Subresource Integrity (SRI) attributes
- Inline scripts without CSP nonce/hash allowance
- Unsafe deserialization indicators (pickle/java serialization markers)
- Dependencies fetched from unverified sources in page markup
"""

import re

from .base import make_finding

CATEGORY = "A08:2021 – Software and Data Integrity Failures"
RANK = 8

SCRIPT_TAG = re.compile(r"<script[^>]*>", re.IGNORECASE)
SRC_ATTR = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
SRI_ATTR = re.compile('integrity=["\']', re.IGNORECASE)
INLINE_SCRIPT = re.compile(r"<script(?![^>]*src=)[^>]*>", re.IGNORECASE)

DESERIALIZATION_MARKERS = [
    r"pickle", r"cPickle", r"java\.io\.Serializable", r"ObjectInputStream",
    r"PHP unserialize", r"yaml\.load", r"eval\(base64",
]


def detect_a08(domain, host, base_urls, http):
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
        except Exception:
            continue

        external_scripts = []
        for m in SCRIPT_TAG.finditer(body):
            tag = m.group(0)
            src = SRC_ATTR.search(tag)
            if src and not SRI_ATTR.search(tag):
                external_scripts.append(src.group(1))

        # 1. External scripts without SRI
        if external_scripts:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A08-SRI-MISSING",
                "MEDIUM", "CWE-345",
                f"{len(external_scripts)} external script(s) loaded without Subresource Integrity on {base}",
                "Scripts loaded without the integrity attribute can be silently swapped at the "
                "CDN/upstream, injecting malicious code into every visitor's session.",
                "Add the integrity attribute (SRI) to all third-party scripts and use a strict "
                "Content-Security-Policy with a nonce.",
                "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                "integrity/sri-missing",
            ))

        # 2. Inline scripts without CSP nonce
        if INLINE_SCRIPT.search(body):
            has_csp_nonce = re.search(r"script-src[^;]*['\"]nonce-", body, re.IGNORECASE)
            if not has_csp_nonce:
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A08-INLINE-SCRIPT-NO-CSP",
                    "LOW", "CWE-345",
                    f"Inline scripts present without CSP nonce on {base}",
                    "Inline scripts execute without a CSP nonce/hash, weakening integrity "
                    "controls against injected code.",
                    "Use CSP with script-src nonces/hashes and eliminate inline handlers.",
                    "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                    "integrity/inline-script",
                ))

        # 3. Unsafe deserialization markers
        if any(re.search(p, body, re.IGNORECASE) for p in DESERIALIZATION_MARKERS):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A08-INSECURE-DESERIALIZATION",
                "HIGH", "CWE-502",
                f"Unsafe deserialization markers in response of {base}",
                "The response references serialization mechanisms (pickle, Java, PHP unserialize) "
                "which, if used on untrusted input, enable remote code execution.",
                "Never deserialize untrusted data. Use safe parsers and signed payloads.",
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Insecure_Deserialization.html",
                "integrity/insecure-deserialization",
            ))

    return findings
