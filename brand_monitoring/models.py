from django.db import models
from django.utils import timezone


class BrandMonitorTarget(models.Model):
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
    )

    domain = models.CharField(
        max_length=255,
        help_text="Domain to monitor (e.g. 'example.com')"
    )
    brand_name = models.CharField(
        max_length=255, blank=True, default='',
        help_text="Optional brand/company name for reference"
    )
    is_active = models.BooleanField(default=True)
    interval_minutes = models.IntegerField(
        default=1440,
        help_text="How often (in minutes) to re-check with VirusTotal (default: 24h)"
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='active'
    )
    last_checked_at = models.DateTimeField(null=True, blank=True)
    org_id = models.CharField(
        max_length=50, default="1",
        help_text="Organization ID for multi-tenant isolation"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Brand Monitor Target"
        verbose_name_plural = "Brand Monitor Targets"
        unique_together = (("domain", "org_id"),)

    def __str__(self):
        return f"[{self.status}] {self.domain}"


class VirusTotalReport(models.Model):
    target = models.ForeignKey(
        BrandMonitorTarget,
        on_delete=models.CASCADE,
        related_name='reports'
    )
    domain = models.CharField(max_length=255)
    malicious = models.IntegerField(default=0)
    suspicious = models.IntegerField(default=0)
    harmless = models.IntegerField(default=0)
    undetected = models.IntegerField(default=0)
    timeout = models.IntegerField(default=0)
    total_engines = models.IntegerField(default=0)
    reputation_score = models.IntegerField(default=0)
    categories = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=list, blank=True)
    raw_response = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, default='')
    org_id = models.CharField(
        max_length=50, default="1",
        help_text="Organization ID for multi-tenant isolation"
    )
    checked_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-checked_at"]
        verbose_name = "Anti Malware Report"
        verbose_name_plural = "Anti Malware Reports"
        indexes = [
            models.Index(fields=['target', '-checked_at']),
        ]

    def __str__(self):
        return f"VT Report for {self.domain} @ {self.checked_at}"


class SuspiciousDomainReport(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )

    domain = models.CharField(max_length=255)
    apex_domain = models.CharField(max_length=255, blank=True, default='')
    resolution_status = models.CharField(max_length=20, default='Inactive') # 'Active' or 'Inactive'
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    mx_record = models.CharField(max_length=255, blank=True, default='')
    name_server = models.CharField(max_length=255, blank=True, default='')
    screenshot_url = models.CharField(max_length=500, blank=True, default='')
    registrar = models.CharField(max_length=255, blank=True, default='')
    whois_created = models.CharField(max_length=100, blank=True, default='')
    whois_raw = models.TextField(blank=True, default='')
    dns_a = models.TextField(blank=True, default='')
    dns_mx = models.TextField(blank=True, default='')
    dns_ns = models.TextField(blank=True, default='')
    dns_txt = models.TextField(blank=True, default='')
    dnsrecon_raw = models.TextField(blank=True, default='')
    reverse_dns = models.TextField(blank=True, default='')
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Suspicious Domain Report"
        verbose_name_plural = "Suspicious Domain Reports"

    def __str__(self):
        return f"Suspicious Domain Report for {self.domain} [{self.status}]"


class PhishingDomainReport(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )

    target = models.ForeignKey(
        BrandMonitorTarget,
        on_delete=models.CASCADE,
        related_name='phishing_reports',
        null=True, blank=True
    )
    domain = models.CharField(max_length=255)
    apex_domain = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # dnstwist classification (e.g., omission, homoglyph, bitsquatting, etc.)
    variation_type = models.CharField(max_length=100, blank=True, default='unknown')
    
    # Resolves
    is_active = models.BooleanField(default=False)
    dns_a = models.TextField(blank=True, default='')
    dns_mx = models.TextField(blank=True, default='')
    dns_ns = models.TextField(blank=True, default='')
    
    # URLScan integration
    urlscan_status = models.CharField(max_length=50, default='unreviewed') # unreviewed, clean, suspicious, malicious
    urlscan_score = models.IntegerField(default=0)
    urlscan_id = models.CharField(max_length=100, blank=True, default='')
    urlscan_raw = models.JSONField(default=dict, blank=True)
    
    # Technology Fingerprinting (httpx)
    page_title = models.CharField(max_length=255, blank=True, default='')
    technologies = models.JSONField(default=list, blank=True)
    server_header = models.CharField(max_length=100, blank=True, default='')
    
    # Screenshot (gowitness / urlscan / microlink)
    screenshot_url = models.CharField(max_length=500, blank=True, default='')
    
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Phishing Domain Report"
        verbose_name_plural = "Phishing Domain Reports"

    def __str__(self):
        return f"Phishing Report: {self.domain} ({self.status})"


# ──────────────────────────────────────────────────────────────────────────────
# Impersonating Account Discovery
# ──────────────────────────────────────────────────────────────────────────────

class ImpersonatingScan(models.Model):
    """A single scan request: (username, brand_domain) → discover imposters."""
    STATUS_CHOICES = (
        ('pending',   'Pending'),
        ('running',   'Running'),
        ('completed', 'Completed'),
        ('failed',    'Failed'),
    )

    username     = models.CharField(max_length=255, help_text="Target username to search across platforms")
    brand_domain = models.CharField(max_length=255, blank=True, default='', help_text="Brand domain this scan is associated with")
    org_name     = models.CharField(max_length=255, blank=True, default='', help_text="Organization name used to generate username permutations (e.g., 'hackers info tech')")
    status       = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    org_id       = models.CharField(max_length=50, default="1")
    created_at   = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Impersonating Scan"

    def __str__(self):
        return f"ImpersonatingScan({self.username}@{self.brand_domain}) [{self.status}]"


class ImpersonatingAccountResult(models.Model):
    """One discovered social-media account that may be impersonating the brand."""
    ACTION_STATUS_CHOICES = (
        ('Unreviewed', 'Unreviewed'),
        ('Take Down',  'Take Down'),
        ('Monitor',    'Monitor'),
        ('Closed',     'Closed'),
        ('In Progress','In Progress'),
    )

    scan          = models.ForeignKey(ImpersonatingScan, on_delete=models.CASCADE, related_name='results')
    org_id        = models.CharField(max_length=50, default="1")

    platform      = models.CharField(max_length=50)         # e.g. "twitter"
    platform_label= models.CharField(max_length=50)         # e.g. "Twitter"
    username      = models.CharField(max_length=255)
    full_name     = models.CharField(max_length=255, blank=True, default='')
    profile_url   = models.URLField(max_length=500, blank=True, default='')
    followers     = models.IntegerField(default=0)
    following     = models.IntegerField(default=0)
    is_private    = models.BooleanField(default=False)

    action_status = models.CharField(max_length=30, choices=ACTION_STATUS_CHOICES, default='Unreviewed')
    action_team   = models.CharField(max_length=255, blank=True, default='')

    source        = models.CharField(max_length=50, default='simulation')  # maigret | sherlock | simulation
    created_at    = models.DateTimeField(default=timezone.now)
    updated_at    = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["platform", "username"]
        verbose_name = "Impersonating Account Result"

    def __str__(self):
        return f"{self.platform_label}: {self.username}"
