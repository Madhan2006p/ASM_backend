"""
OWASP Scanner Django Models
============================
Stores scan sessions, findings, CVE mappings, and reports.
"""
from __future__ import annotations

import json
import uuid
from django.db import models
from django.utils import timezone
from targets.models import Target


# ─── Enums / Choices ──────────────────────────────────────────────────────────

class Severity(models.TextChoices):
    INFO     = 'INFO',     'Informational'
    LOW      = 'LOW',      'Low'
    MEDIUM   = 'MEDIUM',   'Medium'
    HIGH     = 'HIGH',     'High'
    CRITICAL = 'CRITICAL', 'Critical'


class Confidence(models.TextChoices):
    LOW    = 'LOW',    'Low'
    MEDIUM = 'MEDIUM', 'Medium'
    HIGH   = 'HIGH',   'High'
    CERTAIN = 'CERTAIN', 'Certain'


class OWASPCategory(models.TextChoices):
    A01 = 'A01', 'A01:2021 - Broken Access Control'
    A02 = 'A02', 'A02:2021 - Cryptographic Failures'
    A03 = 'A03', 'A03:2021 - Injection'
    A04 = 'A04', 'A04:2021 - Insecure Design'
    A05 = 'A05', 'A05:2021 - Security Misconfiguration'
    A06 = 'A06', 'A06:2021 - Vulnerable and Outdated Components'
    A07 = 'A07', 'A07:2021 - Identification and Authentication Failures'
    A08 = 'A08', 'A08:2021 - Software and Data Integrity Failures'
    A09 = 'A09', 'A09:2021 - Security Logging and Monitoring Failures'
    A10 = 'A10', 'A10:2021 - Server-Side Request Forgery (SSRF)'


class ScanStatus(models.TextChoices):
    PENDING   = 'PENDING',   'Pending'
    RUNNING   = 'RUNNING',   'Running'
    COMPLETED = 'COMPLETED', 'Completed'
    FAILED    = 'FAILED',    'Failed'
    CANCELLED = 'CANCELLED', 'Cancelled'


# ─── Models ───────────────────────────────────────────────────────────────────

class OWASPScanSession(models.Model):
    """Top-level scan session tracking."""
    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target     = models.ForeignKey(Target, on_delete=models.SET_NULL, null=True, blank=True, related_name='owasp_sessions')
    target_url = models.URLField(max_length=2048)
    status     = models.CharField(max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING)
    scan_config = models.JSONField(default=dict, blank=True)

    # OWASP categories to run (empty = all)
    categories = models.JSONField(default=list, blank=True, help_text='List of OWASP category codes to scan. Empty = all.')

    # Progress
    progress_percent  = models.FloatField(default=0.0)
    current_phase     = models.CharField(max_length=100, blank=True, default='')
    phases_completed  = models.JSONField(default=list, blank=True)

    # Timestamps
    created_at   = models.DateTimeField(auto_now_add=True)
    started_at   = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)

    # Celery
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)

    # Summary counters
    total_findings  = models.IntegerField(default=0)
    critical_count  = models.IntegerField(default=0)
    high_count      = models.IntegerField(default=0)
    medium_count    = models.IntegerField(default=0)
    low_count       = models.IntegerField(default=0)
    info_count      = models.IntegerField(default=0)

    # Error message
    error_message = models.TextField(blank=True, null=True)

    # Report files
    report_json = models.CharField(max_length=1024, blank=True, null=True)
    report_html = models.CharField(max_length=1024, blank=True, null=True)
    report_pdf  = models.CharField(max_length=1024, blank=True, null=True)
    report_csv  = models.CharField(max_length=1024, blank=True, null=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OWASP Scan Session'
        verbose_name_plural = 'OWASP Scan Sessions'

    def __str__(self) -> str:
        return f"OWASP Scan [{self.status}] {self.target_url} @ {self.created_at:%Y-%m-%d %H:%M}"

    def update_counters(self) -> None:
        qs = self.findings.all()
        self.total_findings = qs.count()
        self.critical_count = qs.filter(severity=Severity.CRITICAL).count()
        self.high_count     = qs.filter(severity=Severity.HIGH).count()
        self.medium_count   = qs.filter(severity=Severity.MEDIUM).count()
        self.low_count      = qs.filter(severity=Severity.LOW).count()
        self.info_count     = qs.filter(severity=Severity.INFO).count()
        self.save(update_fields=['total_findings', 'critical_count', 'high_count',
                                  'medium_count', 'low_count', 'info_count'])


class DiscoveredAsset(models.Model):
    """Assets discovered during the crawl phase."""
    ASSET_TYPES = [
        ('URL',        'URL'),
        ('API',        'API Endpoint'),
        ('FORM',       'Form'),
        ('PARAM',      'Parameter'),
        ('JS_FILE',    'JavaScript File'),
        ('DIR',        'Directory'),
        ('ROBOTS',     'Robots.txt'),
        ('SITEMAP',    'Sitemap'),
        ('AUTH_PAGE',  'Authentication Page'),
    ]

    session     = models.ForeignKey(OWASPScanSession, on_delete=models.CASCADE, related_name='assets')
    asset_type  = models.CharField(max_length=20, choices=ASSET_TYPES)
    url         = models.TextField()
    method      = models.CharField(max_length=10, default='GET')
    params      = models.JSONField(default=dict, blank=True)
    forms       = models.JSONField(default=list, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=200, blank=True, null=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['asset_type', 'url']
        verbose_name = 'Discovered Asset'

    def __str__(self) -> str:
        return f"[{self.asset_type}] {self.url[:120]}"


class OWASPFinding(models.Model):
    """A single vulnerability finding with full detail."""
    id      = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(OWASPScanSession, on_delete=models.CASCADE, related_name='findings')

    # Classification
    name           = models.CharField(max_length=512)
    owasp_category = models.CharField(max_length=10, choices=OWASPCategory.choices)
    owasp_name     = models.CharField(max_length=255, blank=True)
    cwe_id         = models.CharField(max_length=50, blank=True, null=True)   # e.g. CWE-79
    capec_id       = models.CharField(max_length=50, blank=True, null=True)   # e.g. CAPEC-86
    vulnerability_type = models.CharField(max_length=100, blank=True)         # SQL Injection, XSS, etc.

    # Severity
    severity   = models.CharField(max_length=20, choices=Severity.choices, default=Severity.INFO)
    confidence = models.CharField(max_length=20, choices=Confidence.choices, default=Confidence.MEDIUM)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=200, blank=True, null=True)

    # CVE / Threat Intel
    cve_ids    = models.JSONField(default=list, blank=True)  # List of CVE strings
    epss_score = models.FloatField(null=True, blank=True)
    epss_percentile = models.FloatField(null=True, blank=True)
    in_cisa_kev = models.BooleanField(default=False)
    exploit_available = models.BooleanField(default=False)
    exploit_references = models.JSONField(default=list, blank=True)

    # Location
    affected_url    = models.TextField()
    affected_param  = models.CharField(max_length=500, blank=True, null=True)
    affected_header = models.CharField(max_length=200, blank=True, null=True)

    # Evidence
    http_request  = models.TextField(blank=True, null=True)
    http_response = models.TextField(blank=True, null=True)
    evidence      = models.TextField(blank=True, null=True)
    proof         = models.TextField(blank=True, null=True)   # Exact match or diff

    # Details
    description     = models.TextField(blank=True)
    risk_description = models.TextField(blank=True)
    business_impact  = models.TextField(blank=True)
    remediation      = models.TextField(blank=True)
    references       = models.JSONField(default=list, blank=True)

    # Source
    detected_by = models.CharField(max_length=100, blank=True)  # e.g. "SQLI_DETECTOR", "NUCLEI"
    is_false_positive = models.BooleanField(default=False)
    is_verified       = models.BooleanField(default=False)
    false_positive_reason = models.TextField(blank=True, null=True)

    # Raw tool output
    raw_data = models.JSONField(default=dict, blank=True)

    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-severity', '-cvss_score', 'owasp_category']
        verbose_name = 'OWASP Finding'
        verbose_name_plural = 'OWASP Findings'

    def __str__(self) -> str:
        return f"[{self.severity}] [{self.owasp_category}] {self.name} - {self.affected_url[:80]}"

    def to_dict(self) -> dict:
        return {
            'id':             str(self.id),
            'name':           self.name,
            'owasp_category': self.get_owasp_category_display(),
            'cwe':            self.cwe_id,
            'capec':          self.capec_id,
            'cve_ids':        self.cve_ids,
            'cvss_score':     self.cvss_score,
            'cvss_vector':    self.cvss_vector,
            'epss_score':     self.epss_score,
            'severity':       self.severity,
            'confidence':     self.confidence,
            'affected_url':   self.affected_url,
            'affected_param': self.affected_param,
            'evidence':       self.evidence,
            'proof':          self.proof,
            'description':    self.description,
            'business_impact': self.business_impact,
            'remediation':    self.remediation,
            'references':     self.references,
            'exploit_available': self.exploit_available,
            'in_cisa_kev':    self.in_cisa_kev,
            'detected_by':    self.detected_by,
            'discovered_at':  self.discovered_at.isoformat() if self.discovered_at else None,
        }


class CVERecord(models.Model):
    """Cached CVE data to avoid repeated API calls."""
    cve_id      = models.CharField(max_length=50, unique=True, db_index=True)
    cvss_score  = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=200, blank=True, null=True)
    severity    = models.CharField(max_length=20, blank=True, null=True)
    description = models.TextField(blank=True)
    cwe_ids     = models.JSONField(default=list, blank=True)
    capec_ids   = models.JSONField(default=list, blank=True)
    references  = models.JSONField(default=list, blank=True)
    published_date  = models.DateField(null=True, blank=True)
    modified_date   = models.DateField(null=True, blank=True)
    in_cisa_kev     = models.BooleanField(default=False)
    epss_score      = models.FloatField(null=True, blank=True)
    epss_percentile = models.FloatField(null=True, blank=True)
    exploit_available = models.BooleanField(default=False)
    exploit_refs    = models.JSONField(default=list, blank=True)
    cpe_matches     = models.JSONField(default=list, blank=True)
    raw_nvd_data    = models.JSONField(default=dict, blank=True)
    cached_at       = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'CVE Record'
        verbose_name_plural = 'CVE Records'

    def __str__(self) -> str:
        return f"{self.cve_id} (CVSS: {self.cvss_score})"


class TechFingerprint(models.Model):
    """Technology fingerprint found during scanning."""
    session  = models.ForeignKey(OWASPScanSession, on_delete=models.CASCADE, related_name='tech_fingerprints')
    name     = models.CharField(max_length=200)
    version  = models.CharField(max_length=100, blank=True, null=True)
    category = models.CharField(max_length=100, blank=True, null=True)
    cpe      = models.CharField(max_length=500, blank=True, null=True)
    source   = models.CharField(max_length=100, blank=True)   # WhatWeb, Wappalyzer, header, etc.
    cve_count = models.IntegerField(default=0)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Technology Fingerprint'

    def __str__(self) -> str:
        version_str = f" {self.version}" if self.version else ""
        return f"{self.name}{version_str} ({self.source})"


class ScannerLog(models.Model):
    """Per-session scanner activity logs."""
    LEVEL_CHOICES = [('DEBUG', 'Debug'), ('INFO', 'Info'), ('WARNING', 'Warning'),
                     ('ERROR', 'Error'), ('CRITICAL', 'Critical')]
    session   = models.ForeignKey(OWASPScanSession, on_delete=models.CASCADE, related_name='scanner_logs')
    level     = models.CharField(max_length=20, choices=LEVEL_CHOICES, default='INFO')
    phase     = models.CharField(max_length=100, blank=True)
    message   = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp']

    def __str__(self) -> str:
        return f"[{self.level}] {self.phase}: {self.message[:80]}"
