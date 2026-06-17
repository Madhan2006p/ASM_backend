import os
from django.db import models
from django.conf import settings


class APKFile(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('ANALYZING', 'Analyzing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    )

    file = models.FileField(upload_to='apk_uploads/')
    original_name = models.CharField(max_length=255)
    file_size = models.BigIntegerField(default=0)
    md5_hash = models.CharField(max_length=64, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.original_name

    def filename(self):
        return os.path.basename(self.file.name)


class APKAnalysis(models.Model):
    SEVERITY_CHOICES = (
        ('INFO', 'Info'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    )

    apk = models.OneToOneField(APKFile, on_delete=models.CASCADE, related_name='analysis')

    package_name = models.CharField(max_length=255, blank=True, null=True)
    version_name = models.CharField(max_length=100, blank=True, null=True)
    version_code = models.CharField(max_length=50, blank=True, null=True)
    min_sdk = models.CharField(max_length=50, blank=True, null=True)
    target_sdk = models.CharField(max_length=50, blank=True, null=True)
    app_name = models.CharField(max_length=255, blank=True, null=True)

    permissions = models.TextField(blank=True, null=True)
    activities = models.TextField(blank=True, null=True)
    services = models.TextField(blank=True, null=True)
    receivers = models.TextField(blank=True, null=True)
    providers = models.TextField(blank=True, null=True)

    dangerous_permissions = models.TextField(blank=True, null=True)
    findings = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='INFO')
    analyzed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Analysis of {self.apk.original_name}"
