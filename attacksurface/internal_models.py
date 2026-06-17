from django.db import models

class InternalNetworkScan(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]
    
    network_range = models.CharField(max_length=255, help_text="e.g., 192.168.1.0/24 or specific IP")
    org_id = models.CharField(max_length=50, default="1")
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default="pending")
    progress = models.IntegerField(default=0)
    agent_id = models.CharField(max_length=100, blank=True, null=True, help_text="ID of the internal scanner agent")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Internal Scan: {self.network_range} ({self.status})"

class InternalAsset(models.Model):
    scan = models.ForeignKey(InternalNetworkScan, on_delete=models.CASCADE, related_name="assets")
    asset_name = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.CharField(max_length=50)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    os = models.CharField(max_length=255, blank=True, null=True)
    is_live = models.BooleanField(default=True)
    ports = models.JSONField(default=list, blank=True, help_text="List of discovered ports and services")
    ssl_info = models.JSONField(default=dict, blank=True, help_text="SSL Certificate metadata")
    risk_score = models.IntegerField(default=0)
    findings = models.JSONField(default=list, blank=True, help_text="List of weak ciphers, expired certs, unsupported OS")
    org_id = models.CharField(max_length=50, default="1")
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-risk_score"]

    def __str__(self):
        return f"{self.ip_address} - {self.hostname}"
