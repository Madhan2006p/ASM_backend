"""A06:2021 – Vulnerable and Outdated Components detector.

Detects version/framework disclosure from HTTP headers and page bodies, then
maps the detected (product, version) to real CVEs using a curated local
knowledge base (Product/Version → CPE range → matching CVEs). This produces
concrete product-based findings with CVE IDs, CVSS scores and NVD references —
no external API needed, so the results are deterministic and instant.
"""

import re

from .base import make_finding, header_map

CATEGORY = "A06:2021 – Vulnerable and Outdated Components"
RANK = 6

# ── Header → tech fingerprint ───────────────────────────────────────────────
TECH_HEADER_PATTERNS = {
    "server": {
        "apache": {"tech": "Apache HTTP Server", "cat": "Web Server"},
        "nginx": {"tech": "Nginx", "cat": "Web Server"},
        "iis": {"tech": "Microsoft IIS", "cat": "Web Server"},
        "openresty": {"tech": "OpenResty", "cat": "Web Server"},
        "caddy": {"tech": "Caddy", "cat": "Web Server"},
        "gunicorn": {"tech": "Gunicorn", "cat": "Web Server"},
        "uvicorn": {"tech": "Uvicorn", "cat": "Web Server"},
        "tomcat": {"tech": "Apache Tomcat", "cat": "Application Server"},
        "jetty": {"tech": "Jetty", "cat": "Application Server"},
        "litespeed": {"tech": "LiteSpeed", "cat": "Web Server"},
        "haproxy": {"tech": "HAProxy", "cat": "Load Balancer"},
    },
    "x-powered-by": {
        "php": {"tech": "PHP", "cat": "Language"},
        "asp.net": {"tech": "ASP.NET", "cat": "Framework"},
        "express": {"tech": "Express", "cat": "Framework"},
        "django": {"tech": "Django", "cat": "Framework"},
        "flask": {"tech": "Flask", "cat": "Framework"},
        "next.js": {"tech": "Next.js", "cat": "Framework"},
        "nuxt": {"tech": "Nuxt", "cat": "Framework"},
        "fastapi": {"tech": "FastAPI", "cat": "Framework"},
    },
    "x-aspnet-version": {
        "": {"tech": "ASP.NET", "cat": "Framework"},
    },
    "x-generator": {
        "drupal": {"tech": "Drupal", "cat": "CMS"},
        "wordpress": {"tech": "WordPress", "cat": "CMS"},
        "joomla": {"tech": "Joomla", "cat": "CMS"},
        "ghost": {"tech": "Ghost", "cat": "CMS"},
    },
    "x-drupal-cache": {
        "": {"tech": "Drupal", "cat": "CMS"},
    },
    "x-pingback": {
        "": {"tech": "WordPress", "cat": "CMS"},
    },
}

# ── Body fingerprints (page HTML) ───────────────────────────────────────────
BODY_FINGERPRINTS = [
    # <meta name="generator" content="WordPress 5.2.3" />
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I),
     lambda m: m.group(1)),
    # <script ... src=".../jquery-3.4.1.min.js" ...>
    (re.compile(r'["\']?([^"\']*jquery[-.]?(\d[\d.]*)\.min\.js)["\']?', re.I),
     lambda m: m.group(2)),
    # <script ... src=".../bootstrap-4.3.1...">
    (re.compile(r'["\']?([^"\']*bootstrap[-.](\d[\d.]*)[^"\']*\.(?:min\.)?js)["\']?', re.I),
     lambda m: m.group(2)),
    # <script src=".../vue@2.6.14...">
    (re.compile(r'["\']?([^"\']*?vue[@-]?(\d[\d.]*)[^"\']*\.(?:min\.)?js)["\']?', re.I),
     lambda m: m.group(2)),
    # <script src=".../react@17.0.2..."> or "react-dom@17.0.2"
    (re.compile(r'["\']?([^"\']*?react(?:-dom)?[@-]?(\d[\d.]*)[^"\']*\.(?:min\.)?js)["\']?', re.I),
     lambda m: m.group(2)),
]

BODY_GENERATOR_MAP = [
    ("wordpress", re.compile(r"wordpress\s*([\d.]+)?", re.I)),
    ("drupal", re.compile(r"drupal\s*([\d.]+)?", re.I)),
    ("joomla", re.compile(r"joomla\s*([\d.]+)?", re.I)),
    ("ghost", re.compile(r"ghost\s*([\d.]+)?", re.I)),
]

# ── Curated product → CVE knowledge base ────────────────────────────────────
# (tech names, version range, CVE, CVSS, severity, CWE, title, description,
#  remediation). Version range is (min, min_inclusive, max, max_inclusive);
# None bounds are open. Entries are conservative and map to real NVD records.
PRODUCT_CVE_KB = [
    # ── Nginx ─────────────────────────────────────────────────────────────
    {
        "techs": ("nginx",),
        "min": None, "min_incl": False, "max": "1.20.0", "max_incl": True,
        "cve": "CVE-2021-23017",
        "cvss": 7.7, "severity": "HIGH", "cwe": "CWE-193",
        "title": "nginx resolver off-by-one heap write",
        "desc": "Off-by-one heap buffer overflow in the nginx resolver that can "
                "be triggered by a crafted DNS response, potentially leading to "
                "remote code execution or worker crash.",
        "remediation": "Upgrade nginx to 1.20.1+ / 1.21.0+, or apply the vendor patch.",
    },
    {
        "techs": ("nginx",),
        "min": "0.5.6", "min_incl": True, "max": "1.13.6", "max_incl": True,
        "cve": "CVE-2017-7529",
        "cvss": 7.5, "severity": "HIGH", "cwe": "CWE-190",
        "title": "nginx range filter integer overflow",
        "desc": "Integer overflow in the nginx range filter allows remote "
                "attackers to obtain sensitive information from cache files "
                "via crafted range requests.",
        "remediation": "Upgrade nginx to 1.13.7+ / 1.12.2+.",
    },
    {
        "techs": ("nginx",),
        "min": "1.9.5", "min_incl": True, "max": "1.15.5", "max_incl": True,
        "cve": "CVE-2018-16843",
        "cvss": 7.5, "severity": "HIGH", "cwe": "CWE-400",
        "title": "nginx HTTP/2 memory exhaustion",
        "desc": "Excessive memory usage in nginx HTTP/2 processing allows a "
                "remote attacker to exhaust worker memory via crafted HTTP/2 "
                "requests.",
        "remediation": "Upgrade nginx to 1.15.6+ / 1.14.1+.",
    },
    {
        "techs": ("nginx",),
        "min": "0.5.6", "min_incl": True, "max": "1.17.7", "max_incl": True,
        "cve": "CVE-2019-20372",
        "cvss": 6.1, "severity": "MEDIUM", "cwe": "CWE-79",
        "title": "nginx error_page request handling XSS",
        "desc": "Improper input validation in nginx error_page handling allows "
                "a reflected XSS when an error page is served for a crafted URI.",
        "remediation": "Upgrade nginx to 1.17.8+ / 1.16.2+.",
    },
    # ── Apache HTTP Server ────────────────────────────────────────────────
    {
        "techs": ("apache http server",),
        "min": "2.4.49", "min_incl": True, "max": "2.4.49", "max_incl": True,
        "cve": "CVE-2021-41773",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-22",
        "title": "Apache path traversal & RCE (CVE-2021-41773)",
        "desc": "Path traversal and file disclosure flaw in Apache HTTP Server "
                "2.4.49 that can be chained to remote code execution via CGI "
                "scripts when the Alias directive is misconfigured.",
        "remediation": "Upgrade Apache to 2.4.50+ immediately (2.4.49 is affected).",
    },
    {
        "techs": ("apache http server",),
        "min": "2.4.49", "min_incl": True, "max": "2.4.50", "max_incl": True,
        "cve": "CVE-2021-42013",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-22",
        "title": "Apache path traversal bypass (CVE-2021-42013)",
        "desc": "Bypass of the CVE-2021-41773 fix using encoded slashes; path "
                "traversal and remote code execution on Apache 2.4.49/2.4.50.",
        "remediation": "Upgrade Apache to 2.4.51+.",
    },
    {
        "techs": ("apache http server",),
        "min": "2.4.17", "min_incl": True, "max": "2.4.38", "max_incl": True,
        "cve": "CVE-2019-0211",
        "cvss": 7.8, "severity": "HIGH", "cwe": "CWE-269",
        "title": "Apache local privilege escalation (CVE-2019-0211)",
        "desc": "Race condition in Apache HTTP Server allows a child process to "
                "gain root privileges and execute arbitrary code via a crafted "
                "scoreboard update.",
        "remediation": "Upgrade Apache to 2.4.39+.",
    },
    {
        "techs": ("apache http server",),
        "min": "2.4.0", "min_incl": True, "max": "2.4.29", "max_incl": True,
        "cve": "CVE-2017-15715",
        "cvss": 6.8, "severity": "MEDIUM", "cwe": "CWE-20",
        "title": "Apache .htaccess newline bypass",
        "desc": "Filename with a trailing newline can bypass mod_rewrite / "
                ".htaccess protections, allowing script execution via crafted "
                "file names.",
        "remediation": "Upgrade Apache to 2.4.30+.",
    },
    # ── PHP ────────────────────────────────────────────────────────────────
    {
        "techs": ("php",),
        "min": "5.0.0", "min_incl": True, "max": "7.3.10", "max_incl": True,
        "cve": "CVE-2019-11043",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-94",
        "title": "PHP-FPM RCE via URL encoding (CVE-2019-11043)",
        "desc": "Remote code execution in PHP-FPM when php-fpm is exposed via "
                "a misconfigured nginx fastcgi configuration with certain URL "
                "path handling.",
        "remediation": "Upgrade PHP to 7.1.33+ / 7.2.24+ / 7.3.11+ or fix the "
                       "nginx fastcgi_split_path_info configuration.",
    },
    {
        "techs": ("php",),
        "min": "5.0.0", "min_incl": True, "max": "8.3.7", "max_incl": True,
        "cve": "CVE-2024-4577",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-121",
        "title": "PHP-CGI argument injection RCE (CVE-2024-4577)",
        "desc": "Argument injection vulnerability in PHP running under "
                "Windows with PHP-CGI allows remote code execution when "
                "Unicode characters are passed through the command line.",
        "remediation": "Upgrade PHP to 8.1.29+ / 8.2.20+ / 8.3.8+, or disable "
                       "PHP-CGI usage.",
    },
    # ── OpenSSL ───────────────────────────────────────────────────────────
    {
        "techs": ("openssl",),
        "min": "1.0.1", "min_incl": True, "max": "1.0.1f", "max_incl": True,
        "cve": "CVE-2014-0160",
        "cvss": 7.5, "severity": "HIGH", "cwe": "CWE-119",
        "title": "OpenSSL Heartbleed (CVE-2014-0160)",
        "desc": "Heartbleed allows remote attackers to read up to 64 KB of "
                "memory, potentially exposing private keys, session cookies "
                "and other secrets.",
        "remediation": "Upgrade OpenSSL to 1.0.1g+ and re-issue certificates.",
    },
    {
        "techs": ("openssl",),
        "min": "1.0.1", "min_incl": True, "max": "1.0.1s", "max_incl": True,
        "cve": "CVE-2016-0800",
        "cvss": 5.9, "severity": "MEDIUM", "cwe": "CWE-327",
        "title": "OpenSSL DROWN attack (CVE-2016-0800)",
        "desc": "DROWN allows an attacker to decrypt TLS traffic by abusing "
                "SSLv2 support on the same or related servers.",
        "remediation": "Disable SSLv2 entirely and upgrade OpenSSL to 1.0.1s+ / "
                       "1.0.2g+.",
    },
    # ── jQuery ─────────────────────────────────────────────────────────────
    {
        "techs": ("jquery",),
        "min": "1.0.0", "min_incl": True, "max": "3.4.99", "max_incl": True,
        "cve": "CVE-2020-11022",
        "cvss": 6.1, "severity": "MEDIUM", "cwe": "CWE-79",
        "title": "jQuery XSS via HTML handling (CVE-2020-11022)",
        "desc": "jQuery versions before 3.5.0 mishandle HTML passed to DOM "
                "manipulation methods, enabling stored/reflected XSS.",
        "remediation": "Upgrade jQuery to 3.5.0+.",
    },
    {
        "techs": ("jquery",),
        "min": "3.0.0", "min_incl": True, "max": "3.3.99", "max_incl": True,
        "cve": "CVE-2019-11358",
        "cvss": 6.1, "severity": "MEDIUM", "cwe": "CWE-1321",
        "title": "jQuery prototype pollution (CVE-2019-11358)",
        "desc": "jQuery before 3.4.0 allows prototype pollution via the "
                "extend() function, which can lead to XSS or property "
                "manipulation.",
        "remediation": "Upgrade jQuery to 3.4.0+.",
    },
    # ── Bootstrap ──────────────────────────────────────────────────────────
    {
        "techs": ("bootstrap",),
        "min": "3.0.0", "min_incl": True, "max": "3.4.0", "max_incl": True,
        "cve": "CVE-2019-8331",
        "cvss": 6.1, "severity": "MEDIUM", "cwe": "CWE-79",
        "title": "Bootstrap XSS in tooltip/popover (CVE-2019-8331)",
        "desc": "Bootstrap before 3.4.1 / 4.3.1 allows XSS through the "
                "tooltip and popover data-template attributes.",
        "remediation": "Upgrade Bootstrap to 3.4.1+ / 4.3.1+.",
    },
    # ── WordPress ──────────────────────────────────────────────────────────
    {
        "techs": ("wordpress",),
        "min": "1.0.0", "min_incl": True, "max": "5.9.9", "max_incl": True,
        "cve": "CVE-2022-21661",
        "cvss": 8.8, "severity": "HIGH", "cwe": "CWE-89",
        "title": "WordPress SQL injection in WP_Query (CVE-2022-21661)",
        "desc": "SQL injection in WordPress core before 5.8.3 via a crafted "
                "taxonomy query, exploitable without authentication in some "
                "configurations.",
        "remediation": "Upgrade WordPress to 5.8.3+ / 5.9+.",
    },
    {
        "techs": ("wordpress",),
        "min": "1.0.0", "min_incl": True, "max": "5.1.0", "max_incl": True,
        "cve": "CVE-2019-9787",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-287",
        "title": "WordPress comment authentication bypass (CVE-2019-9787)",
        "desc": "WordPress before 5.1.1 allows crafted URLs in comments to "
                "bypass authentication and cause stored XSS / CSRF.",
        "remediation": "Upgrade WordPress to 5.1.1+.",
    },
    # ── Drupal / Joomla / Tomcat ───────────────────────────────────────────
    {
        "techs": ("drupal",),
        "min": "7.0.0", "min_incl": True, "max": "7.57", "max_incl": True,
        "cve": "CVE-2018-7600",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-94",
        "title": "Drupalgeddon2 RCE (CVE-2018-7600)",
        "desc": "Drupal core before 7.58 / 8.3.9 / 8.4.6 / 8.5.1 allows "
                "unauthenticated remote code execution through the Form API.",
        "remediation": "Upgrade Drupal to 7.58+ / 8.5.1+ immediately.",
    },
    {
        "techs": ("joomla",),
        "min": "1.5.0", "min_incl": True, "max": "3.9.24", "max_incl": True,
        "cve": "CVE-2015-8562",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-94",
        "title": "Joomla object injection RCE (CVE-2015-8562)",
        "desc": "Joomla! before 3.4.6 allows remote code execution via "
                "crafted User-Agent headers processed by the Session handler.",
        "remediation": "Upgrade Joomla to 3.4.6+.",
    },
    {
        "techs": ("apache tomcat",),
        "min": "6.0.0", "min_incl": True, "max": "9.0.30", "max_incl": True,
        "cve": "CVE-2020-1938",
        "cvss": 9.8, "severity": "CRITICAL", "cwe": "CWE-502",
        "title": "Apache Tomcat Ghostcat (CVE-2020-1938)",
        "desc": "Ghostcat allows arbitrary file read / inclusion via the AJP "
                "connector on port 8009 when exposed to the network.",
        "remediation": "Upgrade Tomcat to a patched release and firewall the "
                       "AJP connector (8009).",
    },
]

# Techs that are pure CDN / WAF — never flag as vulnerable products.
SKIP_TECHS = {"cloudflare", "akamai", "aws", "azure", "vercel", "netlify",
              "fastly", "incapsula", "imperva", "sucuri", "stackpath"}


# ── Version helpers ─────────────────────────────────────────────────────────

def _ver_key(version):
    """Split '1.18.0' → [1, 18, 0] for comparison (int segments only)."""
    if not version:
        return []
    return [int(seg) for seg in re.findall(r"\d+", str(version))]


def _pad(key, length):
    """Zero-pad a numeric version key so 7.3 == 7.3.0 for comparisons."""
    return key + [0] * (length - len(key))


def _version_in_range(version, min_v, min_incl, max_v, max_incl):
    """True when ``min OP version OP max`` (None bounds are open).

    Version keys are zero-padded to equal length before comparison, so
    ``7.3`` and ``7.3.0`` are treated as the same version and a bound of
    ``7.3`` correctly covers every ``7.3.x`` release.
    """
    tv = _ver_key(version)
    if not tv:
        return False
    width = max(len(tv),
                len(_ver_key(min_v)) if min_v else 0,
                len(_ver_key(max_v)) if max_v else 0)
    tv = _pad(tv, width)
    if min_v:
        mv = _pad(_ver_key(min_v), width)
        if tv < mv or (not min_incl and tv == mv):
            return False
    if max_v:
        mv = _pad(_ver_key(max_v), width)
        if tv > mv or (not max_incl and tv == mv):
            return False
    return True


def _lookup_product_cves(tech, version):
    """Return KB entries matching (tech, version); [] when none match."""
    tech = (tech or "").strip().lower()
    if not version or tech in SKIP_TECHS:
        return []
    return [
        entry for entry in PRODUCT_CVE_KB
        if tech in entry["techs"]
        and _version_in_range(version, entry["min"], entry["min_incl"],
                              entry["max"], entry["max_incl"])
    ]


# ── Fingerprinting helpers ──────────────────────────────────────────────────

def _extract_version(value):
    """Pull the first dotted version from a header value."""
    m = re.search(r"(\d+(?:\.\d+)+(?:[-.][0-9A-Za-z]+)*)", str(value))
    return m.group(1) if m else ""


def _fingerprint_headers(hdrs):
    """Yield (tech, version, category) tuples from response headers."""
    out = []
    for header, techs in TECH_HEADER_PATTERNS.items():
        value = hdrs.get(header, "")
        if not value:
            continue
        low = value.lower()
        for marker, info in techs.items():
            if not marker or marker in low:
                version = _extract_version(value)
                out.append((info["tech"], version, info["cat"]))
    return out


def _fingerprint_body(text):
    """Yield (tech, version) tuples from page HTML (meta generator + script src)."""
    out = []
    if not text:
        return out
    # meta generator (WordPress/Drupal/Joomla/Ghost with optional version)
    for m in BODY_FINGERPRINTS[0][0].finditer(text):
        content = m.group(1).strip()
        for tech, regex in BODY_GENERATOR_MAP:
            gm = regex.search(content)
            if gm:
                out.append((tech, gm.group(1) or ""))
                break
    # script src fingerprints (jQuery / Bootstrap / Vue / React)
    for idx in range(1, len(BODY_FINGERPRINTS)):
        pattern, getter = BODY_FINGERPRINTS[idx]
        for m in pattern.finditer(text):
            version = getter(m)
            if version:
                tech = ("jquery", "bootstrap", "vue", "react")[idx - 1]
                out.append((tech, version))
    return out


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
            body = resp.text or ""
        except Exception:
            continue

        fingerprints = _fingerprint_headers(hdrs)
        fingerprints += _fingerprint_body(body)

        if not fingerprints:
            continue

        for tech, version, _cat in fingerprints:
            # 1) Product CVE knowledge-base match → real CVE findings
            cve_entries = _lookup_product_cves(tech, version)
            for entry in cve_entries:
                add(make_finding(
                    domain, host, CATEGORY, RANK, f"A06-{entry['cve'].replace('-', '')}",
                    entry["severity"], entry["cwe"],
                    f"{entry['title']} — {entry['cve']} on {base}",
                    f"{entry['desc']} Detected: {tech} {version}.",
                    entry["remediation"],
                    f"https://nvd.nist.gov/vuln/detail/{entry['cve']}",
                    f"components/cve/{entry['cve'].lower()}",
                    cve=entry["cve"],
                    confidence=0.9,
                    status="confirmed",
                    evidence=f"{tech} {version} disclosed via {base}; matches "
                             f"NVD record {entry['cve']} (CVSS {entry['cvss']}).",
                ))

            # 2) Version disclosure without a KB match → informational finding
            if version and not cve_entries:
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A06-COMPONENT-VERSION-DISCLOSED",
                    "LOW", "CWE-200",
                    f"{tech} version disclosed ({version}) on {base}",
                    f"The server discloses {tech} version {version}, letting attackers "
                    f"match known exploits precisely.",
                    "Suppress version strings in headers and error pages.",
                    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                    "components/version-disclosed",
                ))

            # 3) Product detected but no version disclosed → informational
            if not version and not cve_entries:
                add(make_finding(
                    domain, host, CATEGORY, RANK, "A06-COMPONENT-DETECTED",
                    "INFO", "CWE-1104",
                    f"{tech} detected on {base}",
                    f"{tech} was fingerprinted on the target but the version is not "
                    f"disclosed, so CVE matching is not possible.",
                    "Keep components patched; review the vendor advisory feed for "
                    "this product.",
                    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                    "components/product-detected",
                ))

    return findings
