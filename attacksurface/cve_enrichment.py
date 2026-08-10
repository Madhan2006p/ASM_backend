"""NVD CVE enrichment for detected technologies.

During an ASM scan, the technology fingerprinting phase discovers components
and (when the server discloses it) their versions — e.g. ``nginx/1.18.0 [HTTPX]``
or ``Apache HTTP Server 2.4.10 [WhatCMS]``. This module queries the official
NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0) for known CVEs that
affect those components and persists them as :class:`VulnerabilityResult`
records (``source_tool="NVD CVE Enrichment"``) so the dashboard / findings API
surfaces real CVE IDs, CVSS scores, descriptions and references.

How matching works
------------------
* Primary query: NVD keyword search ``"<tech> <version>"`` — catches CVEs whose
  description names the exact version (e.g. "Apache HTTP Server 2.4.49").
* Fallback query (when the keyword search returns nothing): search the tech
  name alone and keep CVEs whose **CPE affected-version range** (from NVD's
  ``configurations``/``cpeMatch`` data) actually includes the disclosed version.
  This is what makes products like nginx work, since their CVE descriptions
  rarely spell out the exact version.

Design notes
------------
* Only components that disclose a **version** are queried — version-less tech
  names produce far too many false positives.
* Results are deduplicated against the DB by ``(scan, template_id, subdomain)``
  matching the rest of the scanner, so re-scans never duplicate findings.
* NVD's public API is rate limited (~5 req / 30 s without an API key), so calls
  are spaced out and capped per scan. An ``NVD_API_KEY`` env var removes the
  sleep and raises the cap.
* All network failures fail open: a CVE lookup hiccup must never abort a scan.
"""

import logging
import os
import re
import time

import httpx

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 8.0
NVD_HEADERS = {"User-Agent": "ASM-CVE-Enrichment/1.0"}

# Without an API key NVD allows ~5 requests / 30 s → 6.5 s spacing is safe.
DEFAULT_REQUEST_INTERVAL = 6.5
DEFAULT_MAX_COMPONENTS = 6  # per scan
MAX_CVES_PER_COMPONENT = 8

# Tech names that are pure infrastructure/CDN and have no real "version → CVE"
# story worth the NVD rate budget. Server headers frequently expose them.
SKIP_TECHS = {
    "cloudflare",
    "akamai",
    "aws",
    "amazon cloudfront",
    "google cloud",
    "azure",
    "vercel",
    "netlify",
    "fastly",
    "incapsula",
    "imperva",
    "sucuri",
    "stackpath",
    "shieldsquare",
}

# Normalise commonly detected display names to a canonical search term.
TECH_ALIASES = {
    "apache http server": "apache",
    "apache": "apache http server",
    "microsoft iis": "iis",
    "iis": "microsoft iis",
    "nginx": "nginx",
    "openresty": "openresty",
    "php": "php",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "laravel": "laravel",
    "express": "express",
    "node.js": "node.js",
    "python": "python",
    "ruby on rails": "ruby on rails",
    "grafana": "grafana",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
    "redis": "redis",
    "mongodb": "mongodb",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "tomcat": "apache tomcat",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "jira": "jira",
    "confluence": "confluence",
}




# ── Parsing ────────────────────────────────────────────────────────────────

def parse_tech_entry(entry):
    """Extract ``(tech_name, version)`` from a technology map entry.

    Handles the formats produced by the ASM fingerprinting pipeline:

    * ``nginx/1.18.0 [HTTPX]``          → (``nginx``, ``1.18.0``)
    * ``Apache HTTP Server 2.4.10 [WhatCMS]`` → (``apache http server``, ``2.4.10``)
    * ``WordPress [Wappalyzer]``        → (``wordpress``, ``""``)
    * ``Cloudflare [Header Analysis]``  → (``cloudflare``, ``""``)

    Returns ``(name, version)`` with version ``""`` when not disclosed.
    """
    if not entry:
        return "", ""
    # Strip the [Source] marker
    text = re.sub(r"\s*\[[^\]]*\]\s*$", "", str(entry)).strip()
    if not text:
        return "", ""

    # "name/version" form (WhatCMS / HTTPX server header)
    if "/" in text:
        left, _, right = text.rpartition("/")
        right = right.strip()
        # only treat the right side as a version when it looks like one
        if right and re.match(r"^\d+(\.\d+)*", right):
            name = left.strip().lower()
            # strip a possible "v" prefix like v1.2.3
            version = re.sub(r"^v", "", right, flags=re.IGNORECASE)
            return name, version

    # "Name ... 1.2.3" trailing-version form
    m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[-_.][0-9A-Za-z]+)*)\s*$", text)
    if m:
        version = m.group(1)
        name = text[: m.start()].strip().rstrip("/").strip().lower()
        if name:
            return name, version

    return text.lower(), ""


def _canonical_tech(name):
    """Normalise a tech name for the NVD keyword query."""
    name = (name or "").strip().lower()
    return TECH_ALIASES.get(name, name)


# ── Version / CPE range matching ───────────────────────────────────────────

def _parse_version(value):
    """Parse a version string into a comparable list of (int|str) segments."""
    if not value:
        return []
    out = []
    for seg in re.findall(r"\d+|[A-Za-z]+", str(value)):
        out.append(int(seg) if seg.isdigit() else seg.lower())
    return out


def _version_in_range(target, start, start_incl, end, end_incl):
    """True when ``target`` satisfies ``start OP v OP end`` (None bounds open).

    Comparison is type-safe: when a target segment and a bound segment are of
    different types (int vs str — e.g. numeric version ``1.18.0`` vs nginx
    Plus edition ``r22``), the bound is **skipped** rather than raising
    ``TypeError``. This is rare but safe: NVD version ranges for a given
    product are always consistent in type, but a single CVE may mix product
    editions (open-source vs plus) in its cpeMatch entries.
    """
    tv = _parse_version(target)
    if not tv:
        return False

    def _cmp(a, b):
        """Return -1, 0, 1 or None (incomparable)."""
        for i in range(max(len(a), len(b))):
            if i >= len(a):
                return -1
            if i >= len(b):
                return 1
            x, y = a[i], b[i]
            if type(x) != type(y):
                return None  # incomparable (e.g. int vs str)
            if x < y:
                return -1
            if x > y:
                return 1
        return 0

    if start:
        sv = _parse_version(start)
        if sv:
            c = _cmp(tv, sv)
            if c is None:
                pass  # incomparable → skip this bound
            elif start_incl and c < 0:
                return False
            elif not start_incl and c <= 0:
                return False
    if end:
        ev = _parse_version(end)
        if ev:
            c = _cmp(tv, ev)
            if c is None:
                pass  # incomparable → skip this bound
            elif end_incl and c > 0:
                return False
            elif not end_incl and c >= 0:
                return False
    return True


def _cpe_match_applies(target_version, match, accept_open_wildcard=False):
    """Does an NVD cpeMatch entry cover the disclosed version?

    Exact-match criteria (``cpe:2.3:a:vendor:product:1.2.3:...``) apply only to
    that exact version; otherwise the entry's start/end bounds decide. Open
    wildcard entries (no version, no bounds) are ignored unless
    ``accept_open_wildcard`` — used only for product-scoped ``cpeName``
    results where a wildcard genuinely means "this product, any version".
    """
    criteria = (match.get("criteria") or "").split(":")
    cpe_version = criteria[5] if len(criteria) > 5 else "*"
    if cpe_version in ("*", "-"):
        cpe_version = None

    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    start_incl = bool(match.get("versionStartIncluding"))
    end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
    end_incl = bool(match.get("versionEndIncluding"))

    # Exact-version criterion (e.g. cpe:2.3:a:nginx:nginx:1.18.0)
    if cpe_version is not None:
        return _parse_version(cpe_version) == _parse_version(target_version)

    # Ranged criterion with explicit bounds
    if start or end:
        return _version_in_range(target_version, start, start_incl, end, end_incl)

    # Open wildcard with no bounds → only accepted in product-scoped queries
    return accept_open_wildcard


def _description_mentions_version(description, version):
    """Cheap fallback: CVE description explicitly names the exact version."""
    if not version or not description:
        return False
    return re.search(r"(?<![\d.])\b" + re.escape(version) + r"\b", description) is not None


def _severity_from_score(score):
    """Map a CVSS base score to a severity label."""
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def _cpe_product_relevant(tech, match):
    """Does the CPE vendor/product refer to the queried tech?

    CPE 2.3 URI: [0]cpe [1]2.3 [2]part [3]vendor [4]product [5]version ...

    The tech must be a whole word in the **vendor** segment, or a whole word
    in the **product** segment provided the product is not a *different*
    product that happens to contain the tech name (e.g. ``nginx_proxy_manager``
    contains ``nginx`` as a word but is not the same product).
    """
    if not tech:
        return True
    criteria = (match.get("criteria") or "").split(":")
    vendor = criteria[3].lower().replace("_", " ") if len(criteria) > 3 else ""
    product = criteria[4].lower().replace("_", " ") if len(criteria) > 4 else ""

    for tok in tech.split():
        # Check vendor first (e.g. "apache" in apache:http_server)
        if re.search(r"(^|[^a-z0-9])" + re.escape(tok) + r"($|[^a-z0-9])", vendor):
            continue
        # Check product — but only if the product name is approximately the
        # same length as the tech (not a compound name like "nginx proxy manager")
        if re.search(r"(^|[^a-z0-9])" + re.escape(tok) + r"($|[^a-z0-9])", product):
            if len(product) <= len(tok) * 1.5:
                continue
        return False
    return True


def _cpe_matches_any(target_version, cve, tech, accept_open_wildcard=False):
    """Does any cpeMatch entry in the CVE cover the disclosed version AND refer
    to the queried product?

    NVD v2.0 returns ``configurations`` as a list (some older shapes wrap a
    dict), each config containing ``nodes`` with ``cpeMatch`` entries.
    """
    configurations = cve.get("configurations") or []
    if isinstance(configurations, dict):
        configurations = [configurations]
    for config in configurations:
        for node in (config or {}).get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if _cpe_product_relevant(tech, match) and _cpe_match_applies(
                    target_version, match, accept_open_wildcard=accept_open_wildcard
                ):
                    return True
    return False


def _parse_cve_item(item, target_version=None, require_tech=None, accept_open_wildcard=False):
    """Extract a clean CVE dict from an NVD v2.0 vulnerability item.

    Relevance rules when ``target_version`` is supplied:
      * the CVE must be linked to the product — either its CPE affected range
        covers the version (vendor/product must match the tech), OR its
        description names the exact version;
      * if ``require_tech`` is given the description must mention that product
        name (guards against NVD keyword-search noise from unrelated CVEs).
    """
    cve = item.get("cve") or {}
    cve_id = (cve.get("id") or "").strip()
    if not cve_id:
        return None

    # English description
    description = ""
    for d in cve.get("descriptions") or []:
        if (d.get("lang") or "").lower().startswith("en"):
            description = (d.get("value") or "").strip()
            break

    if require_tech:
        desc_lower = description.lower()
        if not all(tok in desc_lower for tok in require_tech.split()):
            return None

    if target_version:
        cpe_matched = _cpe_matches_any(
            target_version, cve, require_tech or "",
            accept_open_wildcard=accept_open_wildcard,
        )
        has_cpe_data = bool(cve.get("configurations"))
        # Trust the CPE affected-range when NVD provides it; description mention
        # is only an acceptable fallback for CVEs with no CPE data at all.
        if not cpe_matched and not (not has_cpe_data and _description_mentions_version(description, target_version)):
            return None

    # CVSS score — prefer v3.1 → v3.0 → v2
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics") or {}
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            if data.get("baseScore") is not None:
                score = float(data["baseScore"])
                break
        if score is not None:
            break

    references = []
    for r in cve.get("references") or []:
        url = (r.get("url") or "").strip()
        if url:
            references.append(url)

    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "severity": _severity_from_score(score),
        "description": description,
        "references": references[:5],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _nvd_request(params, retries=2):
    """NVD API call with a small retry/backoff for transient errors, fail-open."""
    for attempt in range(retries + 1):
        try:
            resp = httpx.get(
                NVD_API,
                params=params,
                headers=NVD_HEADERS,
                timeout=NVD_TIMEOUT,
                verify=False,
            )
            if resp.status_code == 403:
                logger.warning("NVD rate limited (403)")
                return None
            if resp.status_code != 200:
                logger.warning("NVD returned HTTP %s", resp.status_code)
                return None
            return resp.json()
        except Exception as exc:
            if attempt < retries:
                time.sleep(1.0 * (attempt + 1))
            else:
                logger.warning("NVD request failed after %d attempts: %s", retries + 1, exc)
    return None


def lookup_cves(tech, version, max_results=MAX_CVES_PER_COMPONENT):
    """Public helper: return CVEs for a (tech, version), most severe first.

    Empty when no version is disclosed or nothing matched.
    """
    if not version:
        return []
    tech = _canonical_tech(tech)

    # 1) Keyword search "tech version" (exact-version descriptions)
    data = _nvd_request({
        "keywordSearch": f"{tech} {version}",
        "resultsPerPage": max_results,
    })
    cves = []
    if data:
        seen = set()
        for item in data.get("vulnerabilities") or []:
            try:
                parsed = _parse_cve_item(item, target_version=version, require_tech=tech)
            except Exception:
                continue
            if not parsed or parsed["cve_id"] in seen:
                continue
            seen.add(parsed["cve_id"])
            cves.append(parsed)

    # 2) Fallback: tech-only keyword + strict CPE affected-range matching.
    #    Only CVEs whose CPE range (versionStart/versionEnd) or an exact CPE
    #    version covers the disclosed version are kept — open-wildcard CPEs
    #    ("affects all versions") are rejected to avoid unrelated products
    #    (e.g. "Nginx Proxy Manager") and ancient plugin CVEs masquerading as
    #    core vulnerabilities.
    if not cves:
        data = _nvd_request({
            "keywordSearch": tech,
            "resultsPerPage": 100,
        })
        if data:
            seen = set()
            for item in data.get("vulnerabilities") or []:
                try:
                    parsed = _parse_cve_item(
                        item, target_version=version, require_tech=tech,
                        accept_open_wildcard=False,
                    )
                except Exception:
                    continue
                if not parsed or parsed["cve_id"] in seen:
                    continue
                seen.add(parsed["cve_id"])
                cves.append(parsed)
            cves = cves[:max_results]

    cves.sort(key=lambda c: (c["cvss_score"] or 0), reverse=True)
    return cves


# ── Scan integration ───────────────────────────────────────────────────────

def enrich_scan_with_technology_cves(scan, combined_tech_map, target):
    """Query NVD for every (tech, version) seen on the scan and store findings.

    ``combined_tech_map`` is the ``{host: [tech entries]}`` map built by
    ``run_full_scan``'s Phase 5. Only entries that disclose a version are
    queried. Returns the number of new ``VulnerabilityResult`` rows created.
    """
    from .models import VulnerabilityResult

    if not combined_tech_map:
        return 0

    api_key = os.environ.get("NVD_API_KEY", "").strip()
    interval = 0.0 if api_key else DEFAULT_REQUEST_INTERVAL
    max_components = int(os.environ.get("NVD_MAX_COMPONENTS", DEFAULT_MAX_COMPONENTS))

    # Collect unique (tech, version) pairs with their hosts
    components = {}
    for host, entries in combined_tech_map.items():
        for entry in entries or []:
            tech, version = parse_tech_entry(entry)
            if not tech or not version:
                continue
            if tech in SKIP_TECHS:
                continue
            key = (tech, version)
            if key not in components:
                components[key] = {"host": host, "tech": tech, "version": version}

    selected = list(components.values())[:max_components]
    if not selected:
        return 0

    logger.info(
        "CVE enrichment: querying NVD for %d components on scan %s (%s)",
        len(selected), scan.id, target,
    )

    created = 0
    for idx, comp in enumerate(selected):
        if idx > 0 and interval:
            time.sleep(interval)
        tech, version, host = comp["tech"], comp["version"], comp["host"]
        cves = lookup_cves(tech, version)
        for cve in cves:
            template_id = f"cve/{cve['cve_id'].lower()}"
            finding_title = (
                f"Known vulnerability in {tech} {version} — {cve['cve_id']}"
            )
            vr, was_created = VulnerabilityResult.objects.get_or_create(
                scan=scan,
                template_id=template_id,
                subdomain=host,
                defaults={
                    "domain": target,
                    "vulnerability_id": cve["cve_id"],
                    "severity": cve["severity"].lower(),
                    "cve": cve["cve_id"],
                    "cwe": "",
                    "finding": finding_title,
                    "description": (
                        cve["description"]
                        or f"{tech} {version} is affected by {cve['cve_id']}."
                    ),
                    "remediation": (
                        f"Upgrade {tech} to a patched version. See the NVD advisory "
                        f"for {cve['cve_id']} for details and vendor fixes."
                    ),
                    "reference": ", ".join(cve["references"]) or cve["nvd_url"],
                    "cvss_score": cve["cvss_score"],
                    "source_tool": "NVD CVE Enrichment",
                    "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                    "owasp_rank": 6,
                    "confidence": 0.9,
                    "finding_status": "confirmed",
                    "evidence": (
                        f"Detected {tech} {version}; CPE match with NVD record for "
                        f"{cve['cve_id']} (CVSS {cve['cvss_score']})"
                    ),
                    "org_id": scan.org_id,
                },
            )
            if was_created:
                created += 1
                logger.info(
                    "  [CVE] %s → %s %s on %s (CVSS %s)",
                    cve["cve_id"], tech, version, host, cve["cvss_score"],
                )

    logger.info("CVE enrichment for scan %s complete: %d new findings", scan.id, created)
    return created
