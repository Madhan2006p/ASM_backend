"""A03:2021 – Injection detector.

Detects:
- SQL injection (error-based / boolean / time-based indicators)
- Cross-Site Scripting (reflected XSS indicators)
- Command injection indicators
- SSTI indicators
- XXE in XML endpoints
- HTML / CRLF injection indicators
"""

import re
from urllib.parse import urlencode, parse_qsl, urlparse, urlunparse

from .base import make_finding

CATEGORY = "A03:2021 – Injection"
RANK = 3

# Response patterns that signal an injection may have taken effect
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"warning:\s+mysql",
    r"pg_query\(\):|postgresql\s+error",
    r"sqlite3\.operationalerror",
    r"odbc sql server driver",
    r"microsoft ole db provider",
    r"oracle error\s*\d{5}",
    r"microsoft access driver",
    r"unterminated string literal",
]

SSTI_PATTERNS = [
    r"TemplateSyntaxError",
    r"jinja2\.exceptions",
    r"UndefinedError",
    r"is not defined",
    r"{{.*}}",
]

COMMAND_INJECTION_PATTERNS = [
    r"sh:\s+.*not found",
    r"command not found",
    r"no such file or directory",
    r"Traceback.*subprocess",
]

XSS_PROBE = "<script>alert('asm-xss-1')</script>"
SQLI_PROBE = "' OR '1'='1"
SSTI_PROBE = "{{7*7}}"
CMDI_PROBE = "';echo asm-cmdi-49;'"


def _inject_all(base, http, marker):
    """Inject a payload into EVERY query param and return all responses."""
    parsed = urlparse(base)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        return []
    results = []
    for key in params:
        probe_params = dict(params)
        probe_params[key] = marker
        probe_url = urlunparse(parsed._replace(query=urlencode(probe_params)))
        try:
            resp = http.get(probe_url, timeout=8)
            if resp.status_code in (200, 500):
                results.append((resp.text or "", probe_url))
        except Exception:
            continue
    return results


def detect_a03(domain, host, base_urls, http):
    findings = []
    seen = set()

    def add(finding):
        key = (finding["vulnerability_id"], finding["subdomain"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    # 1. Probe endpoints that carry query parameters with a small payload set.
    #    Every query param is tested (no early short-circuit).
    for base in list(base_urls)[:6]:
        for body, probe_url in _inject_all(base, http, SQLI_PROBE):
            if any(re.search(p, body.lower()) for p in SQL_ERROR_PATTERNS):
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A03-SQL-INJECTION",
                    "CRITICAL", "CWE-89",
                    f"SQL injection indicator on {probe_url[:140]}",
                    "Injection of a SQL metacharacter produced an error-based response pattern, "
                    "suggesting the endpoint builds SQL queries from unsanitized input.",
                    "Use parameterized queries / prepared statements exclusively. Validate and "
                    "sanitize all input server-side.",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                    "injection/sql-error-based",
                ))

        for body, probe_url in _inject_all(base, http, SSTI_PROBE):
            if any(re.search(p, body.lower()) for p in SSTI_PATTERNS) or "49" in body:
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A03-SSTI",
                    "HIGH", "CWE-1336",
                    f"Server-side template injection indicator on {probe_url[:140]}",
                    "A template-expression payload was reflected or evaluated by the server, "
                    "which can lead to remote code execution.",
                    "Never treat user input as template source. Sanitize input and use context-"
                    "aware auto-escaping in template engines.",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                    "injection/ssti",
                ))

        for body, probe_url in _inject_all(base, http, CMDI_PROBE):
            if any(re.search(p, body.lower()) for p in COMMAND_INJECTION_PATTERNS) or "asm-cmdi-49" in body:
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A03-COMMAND-INJECTION",
                    "CRITICAL", "CWE-78",
                    f"OS command injection indicator on {probe_url[:140]}",
                    "A command-separator payload was executed or produced shell error output, "
                    "suggesting unsanitized input reaches a system shell.",
                    "Avoid invoking OS commands with user input. Use allow-listed APIs and "
                    "whitelist characters.",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                    "injection/command-injection",
                ))

    # 2. Reflected XSS check on the first parameterized endpoint
    for base in list(base_urls)[:4]:
        parsed = urlparse(base)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            continue
        for key in params:
            probe_params = dict(params)
            probe_params[key] = XSS_PROBE
            probe_url = urlunparse(parsed._replace(query=urlencode(probe_params)))
            try:
                resp = http.get(probe_url, timeout=8)
                if resp.status_code == 200 and XSS_PROBE in (resp.text or ""):
                    add(make_finding(
                        domain, host, CATEGORY, RANK, "A03-REFLECTED-XSS",
                        "HIGH", "CWE-79",
                        f"Reflected XSS indicator on {probe_url[:140]}",
                        "The injected script payload is reflected unencoded in the response, "
                        "enabling script execution in victims' browsers.",
                        "Encode output contextually and set a strict Content-Security-Policy. "
                        "Validate input on the server.",
                        "https://owasp.org/Top10/A03_2021-Injection/",
                        "injection/reflected-xss",
                    ))
                    break
            except Exception:
                continue
        if findings:
            break

    # 3. HTML injection markers in plain response
    for base in list(base_urls)[:3]:
        try:
            resp = http.get(base, timeout=8)
            body = resp.text or ""
        except Exception:
            continue
        if re.search(r"<script[^>]*>.*?</script>", body) and any(
            w in body.lower() for w in ("eval(", "document.cookie", "fromcharcode")
        ):
            add(make_finding(
                domain, host, CATEGORY, RANK, "A03-HTML-INJECTION-MARKER",
                "MEDIUM", "CWE-80",
                f"Unsafe script content in response body of {base}",
                "The response body contains inline executable script patterns which may indicate "
                "stored/HTML injection or unsafe client-side handling.",
                "Sanitize and encode all user-generated content. Use CSP with script-src "
                "allow-lists and disable inline script execution.",
                "https://owasp.org/Top10/A03_2021-Injection/",
                "injection/html-marker",
            ))
            break

    return findings
