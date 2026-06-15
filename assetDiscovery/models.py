from django.db import models

from attacksurface.models import SubdomainResult
from scans.models import MonitorSchedule, Scan
from targets.models import Endpoint as TargetEndpoint
from targets.models import Target


class Domain(Target):
    class Meta:
        proxy = True
        verbose_name = "Domain"
        verbose_name_plural = "Domains"


class Endpoint(TargetEndpoint):
    class Meta:
        proxy = True
        verbose_name = "Endpoint"
        verbose_name_plural = "Endpoints"


class ScanEngine(MonitorSchedule):
    class Meta:
        proxy = True
        verbose_name = "Scan Engine"
        verbose_name_plural = "Scan Engines"


class ScanHistory(Scan):
    class Meta:
        proxy = True
        verbose_name = "Scan History"
        verbose_name_plural = "Scan History"


class Subdomain(SubdomainResult):
    class Meta:
        proxy = True
        verbose_name = "Subdomain"
        verbose_name_plural = "Subdomains"


class TestSSLScan(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="testssl_records")
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="testssl_records")
    host = models.CharField(max_length=255)
    port = models.CharField(max_length=10, default="443")
    ip = models.CharField(max_length=100, blank=True, null=True)
    grade = models.CharField(max_length=10, blank=True, null=True)
    scanned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "TestSSL Scan"
        verbose_name_plural = "TestSSL Scans"

    def __str__(self):
        return f"{self.host}:{self.port} - {self.grade or 'N/A'}"


class TestSslRating(models.Model):
    testssl_scan = models.ForeignKey(TestSSLScan, on_delete=models.CASCADE, related_name="ratings")
    metric = models.CharField(max_length=255, blank=True, null=True)
    score = models.CharField(max_length=50, blank=True, null=True)
    finding = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Test ssl rating"
        verbose_name_plural = "Test ssl ratings"

    def __str__(self):
        return self.metric or f"Rating {self.pk}"


class TestSslProtocol(models.Model):
    testssl_scan = models.ForeignKey(TestSSLScan, on_delete=models.CASCADE, related_name="protocols")
    protocol = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=100, blank=True, null=True)
    finding = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Test ssl protocol"
        verbose_name_plural = "Test ssl protocols"

    def __str__(self):
        return self.protocol or f"Protocol {self.pk}"


class TestSslCipher(models.Model):
    testssl_scan = models.ForeignKey(TestSSLScan, on_delete=models.CASCADE, related_name="ciphers")
    cipher = models.CharField(max_length=255, blank=True, null=True)
    key_size = models.CharField(max_length=50, blank=True, null=True)
    strength = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=100, blank=True, null=True)
    finding = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Test ssl cipher"
        verbose_name_plural = "Test ssl ciphers"

    def __str__(self):
        return self.cipher or f"Cipher {self.pk}"


class TestSslBrowserSimulation(models.Model):
    testssl_scan = models.ForeignKey(
        TestSSLScan,
        on_delete=models.CASCADE,
        related_name="browser_simulations",
    )
    client = models.CharField(max_length=255, blank=True, null=True)
    version = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=100, blank=True, null=True)
    cipher = models.CharField(max_length=255, blank=True, null=True)
    dh_key_exchange = models.CharField(max_length=255, blank=True, null=True)
    key_size = models.CharField(max_length=50, blank=True, null=True)
    finding = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Test ssl browser simulation"
        verbose_name_plural = "Test ssl browser simulations"

    def __str__(self):
        return self.client or f"Browser simulation {self.pk}"


class TestSslServerDefault(models.Model):
    testssl_scan = models.ForeignKey(
        TestSSLScan,
        on_delete=models.CASCADE,
        related_name="server_defaults",
    )
    setting = models.CharField(max_length=255, blank=True, null=True)
    value = models.TextField(blank=True, null=True)
    finding = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Test ssl server default"
        verbose_name_plural = "Test ssl server defaults"

    def __str__(self):
        return self.setting or f"Server default {self.pk}"


class TestSslServerPreference(models.Model):
    testssl_scan = models.ForeignKey(
        TestSSLScan,
        on_delete=models.CASCADE,
        related_name="server_preferences",
    )
    preference_type = models.CharField(max_length=255, blank=True, null=True)
    value = models.TextField(blank=True, null=True)
    finding = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Test ssl server preference"
        verbose_name_plural = "Test ssl server preferences"

    def __str__(self):
        return self.preference_type or f"Server preference {self.pk}"


class TestSslVulnerability(models.Model):
    testssl_scan = models.ForeignKey(
        TestSSLScan,
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    vulnerability = models.CharField(max_length=255, blank=True, null=True)
    severity = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=100, blank=True, null=True)
    finding = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Test ssl vulnerability"
        verbose_name_plural = "Test ssl vulnerabilities"

    def __str__(self):
        return self.vulnerability or f"Vulnerability {self.pk}"
