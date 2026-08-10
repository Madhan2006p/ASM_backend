"""
OWASP Scanner - CVE Mapper / NVD API Client
============================================
Maps detected vulnerabilities to CVE IDs, CVSS, CWE, CAPEC.
Sources: NVD, CISA KEV, EPSS, OSV.dev
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger('scanner.cve_mapper')


NVD_API_URL    = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CISA_KEV_URL   = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
OSV_API_URL    = 'https://api.osv.dev/v1/query'
EPSS_API_URL   = 'https://api.first.org/data/v1/epss'
GHSA_SEARCH_URL = 'https://api.github.com/advisories'


class CVEMapper:
    """
    Async CVE lookup engine with caching.
    Uses Django DB cache when available, falls back to in-memory.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cve_cfg = config.get('cve_mapping', {})
        self.nvd_api_key = os.environ.get('NVD_API_KEY', self.cve_cfg.get('nvd_api_key', ''))
        self.cache_ttl = int(self.cve_cfg.get('cache_ttl_hours', 24)) * 3600

        # In-memory cache (also backed by Django ORM when available)
        self._mem_cache: Dict[str, Dict] = {}
        self._kev_set: Set[str] = set()
        self._kev_loaded = False
        self._rate_limiter = asyncio.Semaphore(5)  # NVD = 5 req/30s w/ key

    async def enrich_finding(self, finding_dict: Dict) -> Dict:
        """
        Given a finding dict, enrich with CVE/CVSS/EPSS/KEV data.
        Returns enriched finding dict.
        """
        # Try CVE IDs already known
        cve_ids = finding_dict.get('cve_ids', [])
        if cve_ids:
            enriched_cves = []
            for cve_id in cve_ids:
                cve_data = await self.get_cve(cve_id)
                if cve_data:
                    enriched_cves.append(cve_data)
            if enriched_cves:
                best = max(enriched_cves, key=lambda c: c.get('cvss_score') or 0)
                finding_dict.update({
                    'cvss_score': best.get('cvss_score'),
                    'cvss_vector': best.get('cvss_vector', ''),
                    'cwe_id': finding_dict.get('cwe_id') or (best.get('cwe_ids', [''])[0] if best.get('cwe_ids') else ''),
                    'in_cisa_kev': any(c.get('in_cisa_kev') for c in enriched_cves),
                    'exploit_available': any(c.get('exploit_available') for c in enriched_cves),
                    'exploit_references': [r for c in enriched_cves for r in c.get('exploit_refs', [])],
                    'references': list(set(
                        finding_dict.get('references', []) +
                        [r for c in enriched_cves for r in c.get('references', [])]
                    )),
                })

        # Try CPE-based lookup for component findings
        cpe = finding_dict.get('raw_data', {}).get('cpe')
        if cpe and not cve_ids:
            cves_by_cpe = await self.search_by_cpe(cpe)
            if cves_by_cpe:
                finding_dict['cve_ids'] = cves_by_cpe[:5]
                # Recurse to enrich those IDs
                return await self.enrich_finding(finding_dict)

        # EPSS lookup
        if finding_dict.get('cve_ids'):
            epss_data = await self.get_epss(finding_dict['cve_ids'])
            if epss_data:
                best_epss = max(epss_data, key=lambda e: e.get('epss', 0))
                finding_dict['epss_score'] = float(best_epss.get('epss', 0))
                finding_dict['epss_percentile'] = float(best_epss.get('percentile', 0))

        return finding_dict

    async def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch and cache CVE details from NVD."""
        cve_id = cve_id.upper()

        # Check memory cache
        if cve_id in self._mem_cache:
            return self._mem_cache[cve_id]

        # Check Django DB cache
        try:
            from ..models import CVERecord
            record = CVERecord.objects.filter(cve_id=cve_id).first()
            if record:
                cached = {
                    'cve_id': record.cve_id,
                    'cvss_score': record.cvss_score,
                    'cvss_vector': record.cvss_vector,
                    'severity': record.severity,
                    'description': record.description,
                    'cwe_ids': record.cwe_ids,
                    'capec_ids': record.capec_ids,
                    'references': record.references,
                    'in_cisa_kev': record.in_cisa_kev,
                    'epss_score': record.epss_score,
                    'exploit_available': record.exploit_available,
                    'exploit_refs': record.exploit_refs,
                    'published_date': str(record.published_date) if record.published_date else None,
                }
                self._mem_cache[cve_id] = cached
                return cached
        except Exception:
            pass

        # Fetch from NVD
        data = await self._fetch_nvd_cve(cve_id)
        if data:
            self._mem_cache[cve_id] = data
            await self._save_cve_to_db(data)
        return data

    async def _fetch_nvd_cve(self, cve_id: str) -> Optional[Dict]:
        """Call NVD API for a single CVE."""
        headers = {'apiKey': self.nvd_api_key} if self.nvd_api_key else {}
        params = {'cveId': cve_id}

        async with self._rate_limiter:
            try:
                async with httpx.AsyncClient(timeout=20) as client:
                    resp = await client.get(NVD_API_URL, headers=headers, params=params)
                    if resp.status_code == 200:
                        return self._parse_nvd_response(resp.json(), cve_id)
                    elif resp.status_code == 429:
                        # Rate limited - wait and retry
                        await asyncio.sleep(6)
                        resp = await client.get(NVD_API_URL, headers=headers, params=params)
                        if resp.status_code == 200:
                            return self._parse_nvd_response(resp.json(), cve_id)
            except Exception as e:
                logger.debug('NVD API error for %s: %s', cve_id, e)
        return None

    def _parse_nvd_response(self, data: Dict, cve_id: str) -> Dict:
        """Parse NVD API v2 response."""
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            return {}

        item = vulnerabilities[0].get('cve', {})
        metrics = item.get('metrics', {})

        # Get best CVSS score (prefer v3.1, then v3.0, then v2)
        cvss_score = None
        cvss_vector = ''
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                m = metrics[version][0]
                cvss_data = m.get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')
                cvss_vector = cvss_data.get('vectorString', '')
                break

        # CWE IDs
        cwe_ids = []
        for weakness in item.get('weaknesses', []):
            for desc in weakness.get('description', []):
                val = desc.get('value', '')
                if val.startswith('CWE-'):
                    cwe_ids.append(val)

        # References
        refs = [r.get('url', '') for r in item.get('references', []) if r.get('url')]

        # Exploit references (exploit-db, github, packetstorm)
        exploit_patterns = ['exploit-db.com', 'github.com/exploit', 'packetstormsecurity',
                            'exploit.in', 'vulhub', 'github.com/PoC']
        exploit_refs = [r for r in refs if any(p in r.lower() for p in exploit_patterns)]
        exploit_available = len(exploit_refs) > 0

        # Description
        desc_list = item.get('descriptions', [])
        description = next((d['value'] for d in desc_list if d.get('lang') == 'en'), '')

        severity = 'INFO'
        if cvss_score is not None:
            if cvss_score >= 9.0: severity = 'CRITICAL'
            elif cvss_score >= 7.0: severity = 'HIGH'
            elif cvss_score >= 4.0: severity = 'MEDIUM'
            elif cvss_score > 0: severity = 'LOW'

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'severity': severity,
            'description': description,
            'cwe_ids': list(set(cwe_ids)),
            'capec_ids': [],
            'references': refs,
            'exploit_available': exploit_available,
            'exploit_refs': exploit_refs,
            'in_cisa_kev': False,  # Updated asynchronously during enrichment
            'published_date': item.get('published', '')[:10] if item.get('published') else None,
        }

    async def search_by_cpe(self, cpe: str, max_results: int = 10) -> List[str]:
        """Search NVD CVEs matching a CPE string."""
        headers = {'apiKey': self.nvd_api_key} if self.nvd_api_key else {}
        params = {'cpeName': cpe, 'resultsPerPage': max_results}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(NVD_API_URL, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    cves = []
                    for v in data.get('vulnerabilities', []):
                        cve_id = v.get('cve', {}).get('id', '')
                        if cve_id:
                            cves.append(cve_id)
                    return cves
        except Exception as e:
            logger.debug('CPE search error for %s: %s', cpe, e)
        return []

    async def search_by_keyword(self, keyword: str, max_results: int = 5) -> List[str]:
        """Keyword search for CVEs."""
        headers = {'apiKey': self.nvd_api_key} if self.nvd_api_key else {}
        params = {'keywordSearch': keyword, 'resultsPerPage': max_results,
                  'keywordExactMatch': False}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(NVD_API_URL, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    return [v.get('cve', {}).get('id', '') for v in data.get('vulnerabilities', []) if v.get('cve', {}).get('id')]
        except Exception as e:
            logger.debug('NVD keyword search error: %s', e)
        return []

    async def get_epss(self, cve_ids: List[str]) -> List[Dict]:
        """Get EPSS scores for a list of CVE IDs."""
        if not cve_ids:
            return []
        params = ','.join(cve_ids[:20])  # API limit
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(EPSS_API_URL, params={'cve': params})
                if resp.status_code == 200:
                    return resp.json().get('data', [])
        except Exception as e:
            logger.debug('EPSS API error: %s', e)
        return []

    async def load_kev(self) -> None:
        """Load CISA KEV catalog into memory."""
        if self._kev_loaded:
            return
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(CISA_KEV_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get('vulnerabilities', [])
                    self._kev_set = {v.get('cveID', '') for v in vulns}
                    self._kev_loaded = True
                    logger.info('Loaded %d CVEs from CISA KEV catalog', len(self._kev_set))
        except Exception as e:
            logger.warning('Failed to load CISA KEV: %s', e)

    async def _is_in_kev(self, cve_id: str) -> bool:
        if not self._kev_loaded:
            await self.load_kev()
        return cve_id in self._kev_set

    async def _save_cve_to_db(self, data: Dict) -> None:
        """Save CVE record to Django DB for caching."""
        try:
            from ..models import CVERecord
            from django.utils import timezone
            import asyncio
            # Run DB save in thread to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._sync_save_cve, data)
        except Exception:
            pass

    def _sync_save_cve(self, data: Dict) -> None:
        try:
            from ..models import CVERecord
            CVERecord.objects.update_or_create(
                cve_id=data['cve_id'],
                defaults={
                    'cvss_score': data.get('cvss_score'),
                    'cvss_vector': data.get('cvss_vector', ''),
                    'severity': data.get('severity', ''),
                    'description': data.get('description', ''),
                    'cwe_ids': data.get('cwe_ids', []),
                    'capec_ids': data.get('capec_ids', []),
                    'references': data.get('references', []),
                    'in_cisa_kev': data.get('in_cisa_kev', False),
                    'epss_score': data.get('epss_score'),
                    'exploit_available': data.get('exploit_available', False),
                    'exploit_refs': data.get('exploit_refs', []),
                }
            )
        except Exception:
            pass


# ─── CPE Builder ──────────────────────────────────────────────────────────────

def build_cpe(product: str, version: str = '', vendor: str = '') -> str:
    """
    Build a CPE 2.3 string for a product.
    Example: build_cpe('nginx', '1.18.0') -> 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'
    """
    product = product.lower().replace(' ', '_')
    vendor = vendor.lower().replace(' ', '_') if vendor else product
    version = version.lower() if version else '*'
    return f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'


# ─── Version-to-CVE mapping for common products ───────────────────────────────

# Maps product name -> list of (version_range, cve_id, cvss, description) tuples
# Used as a fast offline fallback when NVD is unavailable
KNOWN_VULNERABLE_VERSIONS: Dict[str, List[Dict]] = {
    'nginx': [
        {'max_version': '1.20.0', 'cve': 'CVE-2021-23017', 'cvss': 8.1, 'desc': 'nginx DNS resolver off-by-one heap write'},
        {'max_version': '1.18.0', 'cve': 'CVE-2021-3618', 'cvss': 9.0, 'desc': 'nginx ALPACA attack'},
    ],
    'apache': [
        {'max_version': '2.4.49', 'exact': True, 'cve': 'CVE-2021-41773', 'cvss': 9.8, 'desc': 'Apache path traversal & RCE'},
        {'max_version': '2.4.50', 'exact': True, 'cve': 'CVE-2021-42013', 'cvss': 9.8, 'desc': 'Apache incomplete fix for 41773'},
    ],
    'openssl': [
        {'max_version': '3.0.6', 'cve': 'CVE-2022-3786', 'cvss': 7.5, 'desc': 'OpenSSL buffer overflow in email validation'},
        {'max_version': '1.1.1l', 'cve': 'CVE-2021-3711', 'cvss': 9.8, 'desc': 'OpenSSL SM2 buffer overflow'},
    ],
    'django': [
        {'max_version': '3.2.14', 'cve': 'CVE-2022-28347', 'cvss': 9.8, 'desc': 'Django SQL injection in QuerySet.annotate'},
        {'max_version': '4.0.5', 'cve': 'CVE-2022-28347', 'cvss': 9.8, 'desc': 'Django SQL injection'},
    ],
    'wordpress': [
        {'max_version': '5.8.3', 'cve': 'CVE-2022-21661', 'cvss': 8.8, 'desc': 'WordPress SQL injection via WP_Query'},
    ],
    'log4j': [
        {'max_version': '2.14.1', 'cve': 'CVE-2021-44228', 'cvss': 10.0, 'desc': 'Log4Shell - Remote Code Execution'},
        {'max_version': '2.15.0', 'cve': 'CVE-2021-45046', 'cvss': 9.0, 'desc': 'Log4j incomplete fix for Log4Shell'},
    ],
    'spring': [
        {'max_version': '5.3.17', 'cve': 'CVE-2022-22965', 'cvss': 9.8, 'desc': 'Spring4Shell - RCE in Spring Framework'},
    ],
    'drupal': [
        {'max_version': '8.9.14', 'cve': 'CVE-2020-13671', 'cvss': 8.8, 'desc': 'Drupal unrestricted file upload'},
    ],
    'tomcat': [
        {'max_version': '9.0.43', 'cve': 'CVE-2021-33037', 'cvss': 5.3, 'desc': 'Apache Tomcat HTTP request smuggling'},
        {'max_version': '10.0.2', 'cve': 'CVE-2021-25122', 'cvss': 7.5, 'desc': 'Apache Tomcat H2C request smuggling'},
    ],
    'php': [
        {'max_version': '8.1.1', 'cve': 'CVE-2022-31626', 'cvss': 8.8, 'desc': 'PHP buffer overflow via user-supplied password'},
        {'max_version': '7.4.29', 'cve': 'CVE-2022-31625', 'cvss': 9.8, 'desc': 'PHP use-after-free in Postgres'},
    ],
}
