from django.db import models
from authentication.models import Organization


class ReconScan(models.Model):
    org = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="recon_scans", null=True, blank=True)
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=50, default="pending")
    progress = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.target


class ToolOutput(models.Model):
    scan = models.ForeignKey(ReconScan, on_delete=models.CASCADE, related_name="tool_outputs")
    tool_name = models.CharField(max_length=100)
    raw_output = models.TextField(blank=True, null=True)
    parsed_output = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.tool_name} - {self.scan.target}"


class DiscoveredDomain(models.Model):
    org = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="discovered_domains", null=True, blank=True)
    scan = models.ForeignKey(ReconScan, on_delete=models.CASCADE, related_name="domains")
    root_domain = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255)
    source = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.subdomain


class ReconEndpoint(models.Model):
    org = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="recon_endpoints", null=True, blank=True)
    scan = models.ForeignKey(ReconScan, on_delete=models.CASCADE, related_name="endpoints")
    url = models.TextField()
    source = models.CharField(max_length=100)
    method = models.CharField(max_length=10, default="GET")
    status_code = models.IntegerField(blank=True, null=True)
    has_params = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
