"""A06:2021 – Vulnerable and Outdated Components detector.

Detects version/framework disclosure and flags known-vulnerable component
versions based on header and body fingerprinting.
"""

import re

from .base import make_finding, header_map

CATEGORY = "A06:2021 – Vulnerable and Outdated Components"
RANK = 6

# Header → tech fingerprint
TECH_HEADER_PATTERNS = {
    "server": {
        "apache": {"tech": "Apache HTTP Server", "cat": "Web Server"},
        "nginx": {"tech": "Nginx", "cat": "Web Server"},
        "iis": {"tech": "Microsoft IIS", "cat": "Web Server"},
        "openresty": {"tech": "OpenResty", "cat": "Web Server"},
        "caddy": {"tech": "Caddy", "cat": "Web Server"},
        "gunicorn": {"tech": "Gunicorn", "cat": "Web Server"},
    },
    "x-powered-by": {
        "php": {"tech": "PHP", "cat": "Language"},
        "asp.net": {"tech": "ASP.NET", "cat": "Framework"},
        "express": {"tech": "Express", "cat": "Framework"},
        "django": {"tech": "Django", "cat": "Framework"},
        "flask": {"tech": "Flask", "cat": "Framework"},
    },
    "x-generator": {
        "drupal": {"tech": "Drupal", "cat": "CMS"},
        "wordpress": {"tech": "WordPress", "cat": "CMS"},
    },
}

# Known vulnerable version ranges (tech, regex, reason) — conservative examples
KNOWN_VULNERABLE = [
    ("Apache HTTP Server", r"2\.4\.(0|1|2|3|4|5|6|7|8|9|10)", "multiple known CVEs pre-2.4.49 (path traversal CVE-2021-41773)"),
    ("Nginx", r"1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\.", "older versions lack modern mitigations"),
    ("PHP", r"5\.[0-9]|7\.[0-3]\.", "end-of-life PHP versions with unpatched vulnerabilities"),
    ("WordPress", r"(0\.|1\.|2\.|3\.|4\.|5\.0|5\.1|5\.2|5\.3)", "older WordPress core with known CVEs"),
    ("Microsoft IIS", r"6\.0|7\.0|7\.5", "end-of-life IIS versions"),
]


def detect_a06(domain, host, base_urls, http):
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
            hdrs = header_map(resp)
        except Exception:
            continue

        fingerprints = []
        for header, techs in TECH_HEADER_PATTERNS.items():
            value = hdrs.get(header, "")
            if not value:
                continue
            low = value.lower()
            for marker, info in techs.items():
                if marker in low:
                    version_match = re.search(r"\d+(\.\d+)+", value)
                    version = version_match.group(0) if version_match else ""
                    fingerprints.append((info["tech"], version, info["cat"]))

        if not fingerprints:
            continue

        for tech, version, cat in fingerprints:
            # Check known-vulnerable versions
            for known_tech, pattern, reason in KNOWN_VULNERABLE:
                if tech == known_tech and version and re.match(pattern, version):
                    add(make_finding(
                        domain, host, CATEGORY, RANK, "A06-VULNERABLE-COMPONENT",
                        "HIGH", "CWE-1104",
                        f"Potentially vulnerable {tech} {version} on {base}",
                        f"{tech} version {version} matches a known-vulnerable range ({reason}). "
                        f"Vulnerable components are a leading cause of compromise.",
                        f"Upgrade {tech} to a supported, patched release and subscribe to "
                        f"vendor security advisories.",
                        f"https://nvd.nist.gov/vuln/search/results?query={tech}+{version}",
                        "components/vulnerable-version",
                    ))
                    break
            else:
                # Version disclosure without known-vulnerable match
                if version:
                    add(make_finding(
                        domain, host, CATEGORY, RANK, "A06-COMPONENT-VERSION-DISCLOSED",
                        "LOW", "CWE-200",
                        f"{tech} version disclosed ({version}) on {base}",
                        f"The server discloses {tech} version {version}, letting attackers match "
                        f"known exploits precisely.",
                        "Suppress version strings in headers and error pages.",
                        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                        "components/version-disclosed",
                    ))

    return findings
