from django.db import models
from targets.models import Target

class Scan(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    )
    SCAN_TYPES = (
        ('DIRSEARCH', 'Dirsearch'),
        ('HTTPX_TECH', 'Httpx Technology Detect'),
        ('INQL', 'InQL GraphQL Introspection'),
        ('GAU', 'GAU Endpoint Fetcher'),
        ('WAYBACKURLS', 'Waybackurls Crawler'),
        ('SWAGGER', 'Swagger Spec Extractor'),
        ('SOAP_WSDL', 'SOAP WSDL Operations Extractor'),
        ('GRPCURL', 'gRPCurl Services Lister'),
        ('ARJUN', 'Arjun Parameter Discovery'),
        ('NUCLEI', 'Nuclei Vulnerability Scan'),
        ('NMAP', 'Nmap Network Scan'),
        ('SSL_CHECK', 'SSL/TLS Check via testssl.sh'),
        ('FULL_WORKFLOW', 'Full API Recon & Discovery Workflow'),
        ('WAPITI', 'Wapiti Web Vulnerability Scanner'),
    )

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    result_file = models.CharField(max_length=512, blank=True, null=True)

    def __str__(self):
        return f"{self.scan_type} on {self.target.domain} - {self.status}"


class SSLResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='ssl_results')
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='ssl_results')
    host = models.CharField(max_length=255)
    port = models.IntegerField(default=443)

    certificate_info = models.TextField(blank=True, null=True)
    protocols = models.TextField(blank=True, null=True)
    cipher_strength = models.CharField(max_length=50, blank=True, null=True)
    vulnerabilities = models.TextField(blank=True, null=True)
    grade = models.CharField(max_length=10, blank=True, null=True)

    raw_json = models.TextField(blank=True, null=True)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"SSL {self.host}:{self.port} - Grade {self.grade or 'N/A'}"


class MonitorSchedule(models.Model):
    FREQUENCY_CHOICES = (
        ('HOURLY', 'Hourly'),
        ('DAILY', 'Daily'),
        ('WEEKLY', 'Weekly'),
        ('MONTHLY', 'Monthly'),
    )

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='monitors')
    name = models.CharField(max_length=100)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES, default='DAILY')
    scan_types = models.TextField(help_text='Comma-separated scan types to run')
    is_active = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.target.domain} ({self.frequency})"


class DetectionResult(models.Model):
    STATUS_CHOICES = (
        ('NEW', 'New'),
        ('CHANGED', 'Changed'),
        ('RESOLVED', 'Resolved'),
        ('UNCHANGED', 'Unchanged'),
    )

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='detections')
    detection_type = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    details = models.TextField(blank=True, null=True)
    previous_value = models.TextField(blank=True, null=True)
    current_value = models.TextField(blank=True, null=True)
    detected_at = models.DateTimeField(auto_now_add=True)
    acknowledged = models.BooleanField(default=False)

    def __str__(self):
        return f"[{self.status}] {self.detection_type} on {self.target.domain}"
