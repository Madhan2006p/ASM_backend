from django.db import models
from targets.models import Target

class Vulnerability(models.Model):
    SEVERITY_CHOICES = (
        ('INFO', 'Info'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    )

    target = models.ForeignKey(Target, related_name='vulnerabilities', on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    description = models.TextField()
    remediation = models.TextField(blank=True)
    discovered_on = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    source_tool = models.CharField(max_length=100) # Nuclei, Wappalyzer, Nmap

    # CVE Integration Fields
    cve_id = models.CharField(max_length=50, blank=True, null=True) # e.g. CVE-2021-34473
    cvss_score = models.FloatField(blank=True, null=True)
    cwe_id = models.CharField(max_length=50, blank=True, null=True) # e.g. CWE-79
    references = models.TextField(blank=True, null=True) # JSON list or raw text of reference links

    def __str__(self):
        prefix = f"[{self.cve_id}] " if self.cve_id else f"[{self.severity}] "
        return f"{prefix}{self.title} on {self.target.domain}"

