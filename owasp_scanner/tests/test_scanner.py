"""
OWASP Scanner Test Suite
"""
from django.test import TestCase
from owasp_scanner.models import OWASPScanSession, OWASPFinding
from owasp_scanner.core import ScanTarget, SeverityLevel, ConfidenceLevel, Finding
from owasp_scanner.cve_mapper.nvd_client import build_cpe


class OWASPScannerTest(TestCase):
    def test_cpe_builder(self):
        cpe = build_cpe('nginx', '1.18.0')
        self.assertEqual(cpe, 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*')

    def test_finding_creation(self):
        finding = Finding(
            name="Test SQLi",
            owasp_category="A03",
            vulnerability_type="SQL Injection",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            affected_url="https://example.com/test",
            cwe_id="CWE-89",
        )
        self.assertEqual(finding.name, "Test SQLi")
        self.assertEqual(finding.severity, "HIGH")
        self.assertTrue(len(finding.fingerprint) > 0)
