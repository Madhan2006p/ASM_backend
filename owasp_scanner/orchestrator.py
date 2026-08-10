"""
OWASP Scanner - Main Orchestrator
===================================
Coordinates all phases of the OWASP scan:
  Phase 1: Asset Discovery (crawl + external tools)
  Phase 2: Vulnerability Detection (all OWASP detectors)
  Phase 3: CVE Enrichment
  Phase 4: Report Generation

This module is the entry point for programmatic use.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

import yaml

from .core import (
    AssetInfo, Finding, ScanTarget,
    RateLimiter, make_http_client, OWASP_NAMES
)
from .scanners.crawler import WebCrawler
from .cve_mapper.nvd_client import CVEMapper
from .tools.tool_runner import (
    run_nuclei, parse_nuclei_finding, run_nmap, run_dirsearch,
    run_gau, run_waybackurls, run_httpx_probe, run_whatweb,
    run_wafw00f, merge_tool_urls
)
from .detectors.a01_broken_access_control import BrokenAccessControlDetector
from .detectors.a02_cryptographic_failures import CryptographicFailuresDetector
from .detectors.a03_injection import InjectionDetector
from .detectors.a04_a08_a09_a10 import (
    InsecureDesignDetector, SSRFDetector,
    DataIntegrityFailuresDetector, LoggingMonitoringDetector
)
from .detectors.a05_security_misconfiguration import SecurityMisconfigurationDetector
from .detectors.a06_outdated_components import OutdatedComponentsDetector
from .detectors.a07_auth_failures import AuthenticationFailuresDetector

logger = logging.getLogger('scanner.orchestrator')


# ─── Configuration Loader ─────────────────────────────────────────────────────

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load scanner configuration from YAML file."""
    if config_path is None:
        config_path = Path(__file__).parent / 'config.yaml'

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Override from environment variables
    if os.environ.get('NVD_API_KEY'):
        config.setdefault('cve_mapping', {})['nvd_api_key'] = os.environ['NVD_API_KEY']

    if os.environ.get('SCANNER_MAX_URLS'):
        config.setdefault('performance', {})['max_urls_to_crawl'] = int(os.environ['SCANNER_MAX_URLS'])

    return config


# ─── Progress Tracking ────────────────────────────────────────────────────────

class ScanProgress:
    """Thread-safe progress tracker for reporting scan phases."""

    PHASES = [
        'Asset Discovery',
        'External Tool Scanning',
        'Technology Fingerprinting',
        'A01 - Broken Access Control',
        'A02 - Cryptographic Failures',
        'A03 - Injection',
        'A04 - Insecure Design',
        'A05 - Security Misconfiguration',
        'A06 - Outdated Components',
        'A07 - Authentication Failures',
        'A08 - Data Integrity',
        'A09 - Logging & Monitoring',
        'A10 - SSRF',
        'CVE Enrichment',
        'Report Generation',
    ]

    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.current_phase = ''
        self.completed_phases: List[str] = []
        self.percent = 0.0
        self._lock = asyncio.Lock()

    async def update(self, phase: str, percent: float) -> None:
        async with self._lock:
            self.current_phase = phase
            self.percent = percent
            if self.callback:
                try:
                    if asyncio.iscoroutinefunction(self.callback):
                        await self.callback(phase, percent)
                    else:
                        self.callback(phase, percent)
                except Exception:
                    pass

    async def complete_phase(self, phase: str) -> None:
        async with self._lock:
            if phase not in self.completed_phases:
                self.completed_phases.append(phase)


# ─── Main Orchestrator ────────────────────────────────────────────────────────

class OWASPScanner:
    """
    Main OWASP Top 10 scanner orchestrator.

    Usage:
        scanner = OWASPScanner(target_url='https://example.com')
        results = await scanner.run()

    Or with Django session:
        scanner = OWASPScanner(
            target_url='https://example.com',
            session_id='uuid-here',
            django_target_id=42,
        )
        results = await scanner.run()
    """

    def __init__(
        self,
        target_url: str,
        session_id: Optional[str] = None,
        django_target_id: Optional[int] = None,
        config: Optional[Dict] = None,
        categories: Optional[List[str]] = None,  # e.g. ['A01', 'A03'] to run specific
        progress_callback: Optional[Callable] = None,
        config_path: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip('/')
        self.session_id = session_id
        self.django_target_id = django_target_id
        self.config = config or load_config(config_path)
        self.categories = categories or []  # empty = all
        self.progress = ScanProgress(callback=progress_callback)

        # Set up target
        self.target = ScanTarget(
            url=self.target_url,
            django_target_id=django_target_id,
            session_id=session_id,
            config=self.config,
        )

        # Results accumulation
        self.all_assets: List[AssetInfo] = []
        self.all_findings: List[Finding] = []
        self.tech_fingerprints: List[Dict] = []
        self.scan_metadata: Dict[str, Any] = {}

        self.rate_limiter = RateLimiter(
            delay=float(self.config.get('performance', {}).get('rate_limit_delay', 0.5))
        )
        self.cve_mapper = CVEMapper(self.config)

        logger.info("OWASPScanner initialized for %s", target_url)

    async def run(self) -> Dict[str, Any]:
        """Execute the full OWASP scan pipeline."""
        start_time = time.monotonic()
        self.scan_metadata['started_at'] = time.time()
        self.scan_metadata['target'] = self.target_url

        try:
            # Phase 1: Asset Discovery
            await self.progress.update("Asset Discovery", 5.0)
            await self._phase_discovery()
            await self.progress.complete_phase("Asset Discovery")
            await self.progress.update("External Tool Scanning", 15.0)

            # Phase 2: External Tool Scanning (parallel with detection)
            await self._phase_external_tools()
            await self.progress.complete_phase("External Tool Scanning")
            await self.progress.update("Vulnerability Detection", 25.0)

            # Phase 3: OWASP Detection (all detectors in parallel)
            await self._phase_detection()
            await self.progress.complete_phase("Vulnerability Detection")
            await self.progress.update("CVE Enrichment", 80.0)

            # Phase 4: CVE Enrichment
            await self._phase_cve_enrichment()
            await self.progress.complete_phase("CVE Enrichment")
            await self.progress.update("Report Generation", 90.0)

            # Phase 5: Save to Django DB
            await self._save_to_database()

            # Phase 6: Build report
            report = await self._build_report(start_time)
            await self.progress.update("Complete", 100.0)

            return report

        except Exception as e:
            logger.error("Scan failed for %s: %s", self.target_url, e, exc_info=True)
            raise

    async def _phase_discovery(self) -> None:
        """Phase 1: Crawl the target and discover all assets."""
        logger.info("Phase 1: Asset Discovery for %s", self.target_url)

        try:
            crawler = WebCrawler(self.target, self.config)
            self.all_assets = await asyncio.wait_for(crawler.crawl(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.warning("Asset discovery phase timed out after 10s. Proceeding with seed asset.")
            self.all_assets = [AssetInfo(url=self.target_url, asset_type='URL')]
        except Exception as e:
            logger.warning("Asset discovery phase error: %s", e)
            self.all_assets = [AssetInfo(url=self.target_url, asset_type='URL')]

        logger.info("Discovery complete: %d assets found", len(self.all_assets))

    async def _phase_external_tools(self) -> None:
        """Phase 2: Run external security tools."""
        logger.info("Phase 2: External Tool Scanning")

        tool_config = self.config.get('tools', {})
        tasks = []

        async def _safe_run(coro, name: str, timeout: float = 20.0):
            try:
                await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("Tool %s timed out after %ss", name, timeout)
            except Exception as e:
                logger.warning("Tool %s failed: %s", name, e)

        # GAU / Wayback URLs for historical endpoint discovery
        if tool_config.get('gau', {}).get('enabled', True):
            tasks.append(_safe_run(self._run_gau_integration(), "gau", 15.0))

        if tool_config.get('waybackurls', {}).get('enabled', True):
            tasks.append(_safe_run(self._run_wayback_integration(), "waybackurls", 15.0))

        # Dirsearch for hidden directories
        if tool_config.get('dirsearch', {}).get('enabled', False):
            tasks.append(_safe_run(self._run_dirsearch_integration(), "dirsearch", 20.0))

        # Nuclei vulnerability scanner
        if tool_config.get('nuclei', {}).get('enabled', True):
            tasks.append(_safe_run(self._run_nuclei_integration(), "nuclei", 30.0))

        # Nmap port scan
        if tool_config.get('nmap', {}).get('enabled', True):
            tasks.append(_safe_run(self._run_nmap_integration(), "nmap", 20.0))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_gau_integration(self) -> None:
        """Run gau and add discovered URLs to assets."""
        try:
            urls = await run_gau(self.target.domain, self.config)
            existing_urls = {a.url for a in self.all_assets}
            for url in urls:
                if url not in existing_urls and url.startswith(self.target_url):
                    self.all_assets.append(AssetInfo(url=url, asset_type='URL'))
                    existing_urls.add(url)
        except Exception as e:
            logger.debug("GAU integration error: %s", e)

    async def _run_wayback_integration(self) -> None:
        """Run waybackurls and add discovered URLs."""
        try:
            urls = await run_waybackurls(self.target.domain, self.config)
            existing_urls = {a.url for a in self.all_assets}
            for url in urls:
                if url not in existing_urls and url.startswith(self.target_url):
                    self.all_assets.append(AssetInfo(url=url, asset_type='URL'))
                    existing_urls.add(url)
        except Exception as e:
            logger.debug("Wayback integration error: %s", e)

    async def _run_dirsearch_integration(self) -> None:
        """Run dirsearch and add new discovered paths."""
        try:
            results = await run_dirsearch(self.target_url, self.config)
            existing_urls = {a.url for a in self.all_assets}
            for result in results:
                url = result.get('url', '')
                if url and url not in existing_urls:
                    self.all_assets.append(AssetInfo(
                        url=url,
                        asset_type='DIR' if url.endswith('/') else 'URL',
                        status_code=result.get('status', 0)
                    ))
                    existing_urls.add(url)
        except Exception as e:
            logger.debug("Dirsearch integration error: %s", e)

    async def _run_nuclei_integration(self) -> None:
        """Run Nuclei and convert findings to our Finding format."""
        try:
            raw_findings = await run_nuclei(self.target_url, self.config)
            for raw in raw_findings:
                parsed = parse_nuclei_finding(raw)
                if parsed:
                    # Map nuclei finding to OWASP category
                    category = self._map_nuclei_to_owasp(parsed)
                    severity = self._map_severity(parsed['severity'])

                    finding = Finding(
                        name=parsed['name'],
                        owasp_category=category,
                        vulnerability_type=parsed.get('template_id', 'Nuclei Finding'),
                        severity=severity,
                        confidence=__import__('owasp_scanner.core', fromlist=['ConfidenceLevel']).ConfidenceLevel.HIGH,
                        affected_url=parsed['affected_url'],
                        description=parsed.get('description', ''),
                        remediation=parsed.get('remediation', ''),
                        references=parsed.get('references', []),
                        cve_ids=parsed.get('cve_ids', []),
                        cvss_score=parsed.get('cvss_score'),
                        evidence=f"Nuclei template: {parsed.get('template_id')}",
                        proof=f"Matcher: {parsed.get('matcher_name')}\nRequest:\n{parsed.get('request', '')[:500]}",
                        http_request=None,
                        http_response=None,
                        detected_by='NUCLEI',
                        raw_data=parsed.get('raw', {}),
                    )
                    self.all_findings.append(finding)
        except Exception as e:
            logger.debug("Nuclei integration error: %s", e)

    async def _run_nmap_integration(self) -> None:
        """Run Nmap and convert service/script findings."""
        try:
            ports = self.config.get('tools', {}).get('nmap', {}).get('ports', '80,443,8080,8443')
            result = await run_nmap(self.target.domain, ports, self.config)

            # Check for risky services and open ports
            for port_info in result.get('ports', []):
                port = port_info.get('port')
                service = port_info.get('service', '')
                version = port_info.get('product', '') + ' ' + port_info.get('version', '')
                version = version.strip()

                # Check for dangerous script outputs
                for script in port_info.get('scripts', []):
                    script_id = script.get('id', '')
                    output = script.get('output', '')

                    if 'vuln' in script_id.lower() or 'VULNERABLE' in output:
                        from .core import ConfidenceLevel as CL, SeverityLevel as SL
                        finding = Finding(
                            name=f"Nmap Script Finding: {script_id} on port {port}",
                            owasp_category='A05',
                            vulnerability_type='Nmap Script Detection',
                            severity=SL.MEDIUM,
                            confidence=CL.MEDIUM,
                            affected_url=f"{self.target_url}:{port}",
                            description=f"Nmap script '{script_id}' on port {port}/{service}: {output[:500]}",
                            remediation="Review the specific vulnerability and apply vendor patches.",
                            detected_by='NMAP',
                            raw_data={'script': script_id, 'output': output, 'port': port},
                        )
                        self.all_findings.append(finding)

        except Exception as e:
            logger.debug("Nmap integration error: %s", e)

    async def _phase_detection(self) -> None:
        """Phase 3: Run all OWASP detectors."""
        logger.info("Phase 3: OWASP Detection (%d assets, %d existing findings)",
                    len(self.all_assets), len(self.all_findings))

        async with make_http_client(self.config) as client:
            detector_classes = self._get_active_detectors()
            tasks = []
            for DetectorClass in detector_classes:
                detector = DetectorClass(
                    target=self.target,
                    client=client,
                    rate_limiter=self.rate_limiter,
                    config=self.config,
                    session_logger=self._session_log,
                )
                tasks.append(self._run_detector(detector))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    self.all_findings.extend(result)
                elif isinstance(result, Exception):
                    logger.error("Detector error: %s", result)

        # Deduplicate
        seen = set()
        unique_findings = []
        for f in self.all_findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_findings.append(f)
        self.all_findings = unique_findings

        logger.info("Detection complete. Total findings: %d", len(self.all_findings))

    async def _run_detector(self, detector) -> List[Finding]:
        """Run a single detector and return its findings."""
        try:
            results = await asyncio.wait_for(detector.detect(self.all_assets), timeout=25.0)
            logger.info("Detector %s: %d findings", detector.name, len(results))
            return results
        except asyncio.TimeoutError:
            logger.warning("Detector %s timed out after 25s. Returning partial findings.", detector.name)
            return getattr(detector, '_findings', [])
        except Exception as e:
            logger.error("Detector %s failed: %s", detector.__class__.__name__, e)
            return []

    def _get_active_detectors(self) -> List:
        """Return list of detector classes to run based on categories config."""
        all_detectors = {
            'A01': BrokenAccessControlDetector,
            'A02': CryptographicFailuresDetector,
            'A03': InjectionDetector,
            'A04': InsecureDesignDetector,
            'A05': SecurityMisconfigurationDetector,
            'A06': OutdatedComponentsDetector,
            'A07': AuthenticationFailuresDetector,
            'A08': DataIntegrityFailuresDetector,
            'A09': LoggingMonitoringDetector,
            'A10': SSRFDetector,
        }

        if not self.categories:
            return list(all_detectors.values())

        return [all_detectors[cat] for cat in self.categories if cat in all_detectors]

    async def _phase_cve_enrichment(self) -> None:
        """Phase 4: Enrich findings with CVE data."""
        logger.info("Phase 4: CVE Enrichment for %d findings", len(self.all_findings))

        # Load CISA KEV list
        await self.cve_mapper.load_kev()

        # Enrich findings that have CVE IDs or are from component detection
        enrich_tasks = []
        for finding in self.all_findings:
            if finding.cve_ids or finding.owasp_category == 'A06':
                enrich_tasks.append(self._enrich_finding(finding))

        if enrich_tasks:
            await asyncio.gather(*enrich_tasks, return_exceptions=True)

    async def _enrich_finding(self, finding: Finding) -> None:
        """Enrich a single finding with CVE data."""
        try:
            finding_dict = finding.to_dict()
            enriched = await self.cve_mapper.enrich_finding(finding_dict)
            # Update finding with enriched data
            if enriched.get('cvss_score') and not finding.cvss_score:
                finding.cvss_score = enriched['cvss_score']
            if enriched.get('cvss_vector') and not finding.cvss_vector:
                finding.cvss_vector = enriched['cvss_vector']
            if enriched.get('in_cisa_kev'):
                finding.in_cisa_kev = True
            if enriched.get('exploit_available'):
                finding.exploit_available = True
            if enriched.get('cve_ids') and not finding.cve_ids:
                finding.cve_ids = enriched['cve_ids']
            if enriched.get('epss_score'):
                finding.epss_score = enriched['epss_score']
                finding.epss_percentile = enriched.get('epss_percentile')
        except Exception as e:
            logger.debug("CVE enrichment error for finding %s: %s", finding.name, e)

    async def _save_to_database(self) -> None:
        """Save all findings and assets to Django database."""
        if not self.session_id:
            return

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._sync_save)
        except Exception as e:
            logger.error("DB save error: %s", e)

    def _sync_save(self) -> None:
        """Synchronous Django DB save."""
        try:
            import django
            from .models import OWASPScanSession, OWASPFinding, DiscoveredAsset, TechFingerprint
            from django.utils import timezone

            session = OWASPScanSession.objects.get(id=self.session_id)

            # Save assets
            for asset in self.all_assets:
                DiscoveredAsset.objects.get_or_create(
                    session=session,
                    url=asset.url,
                    defaults={
                        'asset_type': asset.asset_type,
                        'method': asset.method,
                        'params': asset.params,
                        'forms': asset.forms,
                        'status_code': asset.status_code,
                        'content_type': asset.content_type,
                    }
                )

            # Save findings
            for finding in self.all_findings:
                OWASPFinding.objects.get_or_create(
                    session=session,
                    name=finding.name[:512],
                    affected_url=finding.affected_url[:2048],
                    owasp_category=finding.owasp_category,
                    vulnerability_type=finding.vulnerability_type[:100],
                    defaults={
                        'owasp_name': OWASP_NAMES.get(finding.owasp_category, ''),
                        'cwe_id': finding.cwe_id[:50] if finding.cwe_id else '',
                        'capec_id': finding.capec_id[:50] if finding.capec_id else '',
                        'severity': finding.severity.value,
                        'confidence': finding.confidence.value,
                        'cvss_score': finding.cvss_score,
                        'cvss_vector': finding.cvss_vector[:200] if finding.cvss_vector else '',
                        'cve_ids': finding.cve_ids,
                        'epss_score': finding.epss_score,
                        'epss_percentile': finding.epss_percentile,
                        'in_cisa_kev': finding.in_cisa_kev,
                        'exploit_available': finding.exploit_available,
                        'exploit_references': finding.exploit_references,
                        'affected_param': finding.affected_param[:500] if finding.affected_param else '',
                        'affected_header': finding.affected_header[:200] if finding.affected_header else '',
                        'http_request': finding.http_request.to_raw() if finding.http_request else '',
                        'http_response': finding.http_response.to_raw() if finding.http_response else '',
                        'evidence': finding.evidence,
                        'proof': finding.proof,
                        'description': finding.description,
                        'risk_description': finding.risk_description,
                        'business_impact': finding.business_impact,
                        'remediation': finding.remediation,
                        'references': finding.references,
                        'detected_by': finding.detected_by[:100],
                        'raw_data': finding.raw_data,
                    }
                )

            # Update session counters
            session.completed_at = timezone.now()
            session.status = 'COMPLETED'
            session.update_counters()

        except Exception as e:
            logger.error("Sync DB save error: %s", e)
            raise

    async def _build_report(self, start_time: float) -> Dict[str, Any]:
        """Build the final scan report."""
        duration = time.monotonic() - start_time

        # Group findings by OWASP category
        by_category: Dict[str, List] = {}
        for finding in self.all_findings:
            cat = finding.owasp_category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(finding.to_dict())

        # Severity summary
        severity_counts = {s: 0 for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']}
        for f in self.all_findings:
            severity_counts[f.severity.value] += 1

        # Top findings by severity
        top_findings = sorted(
            self.all_findings,
            key=lambda x: (
                ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x.severity.value),
                -(x.cvss_score or 0)
            )
        )[:20]

        report = {
            'summary': {
                'target': self.target_url,
                'scan_duration_seconds': round(duration, 2),
                'total_assets_discovered': len(self.all_assets),
                'total_findings': len(self.all_findings),
                'severity_breakdown': severity_counts,
                'categories_detected': list(by_category.keys()),
                'risk_score': self._calculate_risk_score(),
            },
            'top_findings': [f.to_dict() for f in top_findings],
            'findings_by_category': {
                cat: {
                    'name': OWASP_NAMES.get(cat, cat),
                    'count': len(findings),
                    'findings': findings,
                }
                for cat, findings in sorted(by_category.items())
            },
            'assets': {
                'total': len(self.all_assets),
                'by_type': {},
            },
            'metadata': {
                **self.scan_metadata,
                'session_id': self.session_id,
            },
        }

        # Asset type breakdown
        for asset in self.all_assets:
            t = asset.asset_type
            report['assets']['by_type'][t] = report['assets']['by_type'].get(t, 0) + 1

        return report

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        score = 0.0
        weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 0.5, 'INFO': 0.1}
        for finding in self.all_findings:
            weight = weights.get(finding.severity.value, 0)
            cvss_multiplier = (finding.cvss_score or 5.0) / 10.0
            if finding.exploit_available:
                cvss_multiplier *= 1.5
            if finding.in_cisa_kev:
                cvss_multiplier *= 2.0
            score += weight * cvss_multiplier
        return round(min(100.0, score), 2)

    def _map_nuclei_to_owasp(self, finding: Dict) -> str:
        """Map a nuclei finding's tags to an OWASP category."""
        tags = [t.lower() for t in finding.get('tags', [])]
        if any(t in tags for t in ['xss', 'sqli', 'injection', 'rce', 'ssti', 'xxe', 'cmd-injection']):
            return 'A03'
        if any(t in tags for t in ['cve', 'lfi', 'rfi', 'path-traversal', 'idor']):
            return 'A01'
        if any(t in tags for t in ['ssl', 'tls', 'crypto']):
            return 'A02'
        if any(t in tags for t in ['config', 'misconfig', 'misconfiguration', 'exposure', 'default-login']):
            return 'A05'
        if any(t in tags for t in ['ssrf']):
            return 'A10'
        if any(t in tags for t in ['auth', 'jwt', 'session']):
            return 'A07'
        if any(t in tags for t in ['outdated', 'version']):
            return 'A06'
        return 'A05'  # Default to misconfiguration

    def _map_severity(self, severity_str: str):
        from .core import SeverityLevel
        mapping = {
            'CRITICAL': SeverityLevel.CRITICAL,
            'HIGH': SeverityLevel.HIGH,
            'MEDIUM': SeverityLevel.MEDIUM,
            'LOW': SeverityLevel.LOW,
            'INFO': SeverityLevel.INFO,
        }
        return mapping.get(severity_str.upper(), SeverityLevel.INFO)

    def _session_log(self, level: str = 'INFO', phase: str = '', message: str = '') -> None:
        """Log a message to the Django scan session."""
        if not self.session_id:
            return
        try:
            from .models import ScannerLog, OWASPScanSession
            session = OWASPScanSession.objects.filter(id=self.session_id).first()
            if session:
                ScannerLog.objects.create(
                    session=session, level=level, phase=phase, message=message[:2000]
                )
        except Exception:
            pass


# ─── Convenience function ──────────────────────────────────────────────────────

async def scan(
    target_url: str,
    categories: Optional[List[str]] = None,
    config: Optional[Dict] = None,
    session_id: Optional[str] = None,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Convenience function to run a scan.

    Args:
        target_url: URL to scan (e.g. 'https://example.com')
        categories: List of OWASP categories to test (e.g. ['A01', 'A03']).
                    Pass None or empty list to test all categories.
        config: Optional config dict override.
        session_id: Optional Django OWASPScanSession UUID.
        progress_callback: Optional async callable(phase, percent) for progress updates.

    Returns:
        Full scan report dictionary.
    """
    scanner = OWASPScanner(
        target_url=target_url,
        categories=categories,
        config=config,
        session_id=session_id,
        progress_callback=progress_callback,
    )
    return await scanner.run()
