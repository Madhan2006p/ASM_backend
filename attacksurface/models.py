from django.db import models


class AttackSurfaceScan(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    target = models.CharField(max_length=255)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default="pending")
    progress = models.IntegerField(default=0)
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Phase completion tracking (each phase flips to True when done)
    subdomains_done = models.BooleanField(default=False)
    # Vulnerability scan sub-phases: "pending" → "basic" (PythonScanner done) → "deep" (Nuclei running) → "complete"
    vuln_scan_phase = models.CharField(max_length=20, default="pending")
    endpoints_done = models.BooleanField(default=False)
    ports_done = models.BooleanField(default=False)
    technologies_done = models.BooleanField(default=False)
    vulnerabilities_done = models.BooleanField(default=False)
    ssl_done = models.BooleanField(default=False)
    email_done = models.BooleanField(default=False)
    directories_done = models.BooleanField(default=False)
    malware_done = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.target} ({self.status})"


class MonitoredDomain(models.Model):
    domain = models.CharField(max_length=255)
    org_id = models.CharField(max_length=50, default="1")
    morning_time = models.TimeField(default="09:00")
    night_time = models.TimeField(default="21:00")
    morning_enabled = models.BooleanField(default=True)
    night_enabled = models.BooleanField(default=True)
    auto_scan_on_add = models.BooleanField(default=True)
    last_morning_scan_at = models.DateTimeField(null=True, blank=True)
    last_night_scan_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("domain", "org_id")
        ordering = ["domain"]

    def __str__(self):
        return self.domain


class SubdomainResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="subdomains"
    )
    domain = models.CharField(max_length=255)
    status = models.CharField(max_length=50, default="Active")
    title = models.CharField(max_length=500, blank=True, null=True)
    technologies = models.JSONField(default=list, blank=True)
    ip = models.JSONField(default=list, blank=True)
    ports = models.JSONField(default=list, blank=True)
    dns_records = models.JSONField(default=list, blank=True)
    vulnerabilities_count = models.IntegerField(default=0)
    waf = models.CharField(max_length=255, blank=True, null=True)
    cdn = models.CharField(max_length=255, blank=True, null=True)
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["domain"]

    def __str__(self):
        return self.domain


class EndpointResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="endpoints"
    )
    http_url = models.TextField()
    subdomain_name = models.CharField(max_length=255, blank=True, null=True)
    http_status = models.IntegerField(blank=True, null=True)
    content_type = models.CharField(max_length=255, blank=True, null=True)
    content_length = models.IntegerField(blank=True, null=True)
    title = models.CharField(max_length=500, blank=True, null=True)
    is_alive = models.BooleanField(default=False)
    technologies = models.JSONField(default=list, blank=True)
    threat_count = models.IntegerField(default=0)
    method = models.CharField(max_length=10, default="GET")
    org_id = models.CharField(max_length=50, default="1")
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_scan = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-discovered_at"]

    def __str__(self):
        return self.http_url


class PortResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="ports"
    )
    domain = models.CharField(max_length=255)
    ports = models.JSONField(default=list, blank=True)
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["domain"]

    def __str__(self):
        return f"{self.domain} - {len(self.ports)} ports"


class DirectoryResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="directories"
    )
    url = models.TextField()
    subdomain_name = models.CharField(max_length=255, blank=True, null=True)
    content_type = models.CharField(max_length=255, blank=True, null=True)
    content_details = models.TextField(blank=True, null=True)
    status = models.IntegerField(blank=True, null=True)
    org_id = models.CharField(max_length=50, default="1")
    directories_created = models.DateTimeField(auto_now_add=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Directory results"
        ordering = ["-created"]

    def __str__(self):
        return self.url


class TechnologyResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="technologies"
    )
    domain = models.CharField(max_length=255)
    technologies = models.JSONField(default=list, blank=True)
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["domain"]

    def __str__(self):
        return f"{self.domain} - {len(self.technologies)} techs"


class VulnerabilityResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="vulnerabilities"
    )
    vulnerability_id = models.CharField(max_length=100, blank=True, null=True)
    domain = models.CharField(max_length=255, blank=True, null=True)
    subdomain = models.CharField(max_length=255, blank=True, null=True)
    severity = models.CharField(max_length=50, blank=True, null=True)
    cve = models.CharField(max_length=100, blank=True, null=True)
    cwe = models.CharField(max_length=100, blank=True, null=True)
    finding = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)
    reference = models.TextField(blank=True, null=True)
    template_id = models.CharField(max_length=255, blank=True, null=True)
    source_tool = models.CharField(max_length=255, blank=True, null=True, default="Nuclei")
    org_id = models.CharField(max_length=50, default="1")
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Vulnerability results"
        ordering = ["-discovered_at"]

    def __str__(self):
        return f"{self.vulnerability_id} - {self.severity}"


class SSLResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="ssl_results"
    )
    domain = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255, blank=True, null=True)
    ip = models.CharField(max_length=255, blank=True, null=True)
    rdns = models.CharField(max_length=255, blank=True, null=True)
    ssl_grade = models.CharField(max_length=10, blank=True, null=True)
    issuer_name = models.CharField(max_length=500, blank=True, null=True)
    expiry_date = models.CharField(max_length=50, blank=True, null=True)
    purchase_date = models.CharField(max_length=50, blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    cipher_suite = models.CharField(max_length=255, blank=True, null=True)
    is_trusted = models.BooleanField(default=True)
    domain_aligned = models.BooleanField(default=True)
    is_shadow_it = models.BooleanField(default=False)
    ip_count = models.IntegerField(default=0)
    dns_count = models.IntegerField(default=0)
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["domain"]

    def __str__(self):
        return f"{self.domain} - {self.ssl_grade}"


class EmailSecurityResult(models.Model):
    scan = models.ForeignKey(
        AttackSurfaceScan, on_delete=models.CASCADE, related_name="email_security"
    )
    domain = models.CharField(max_length=255)
    root_txt = models.JSONField(default=list, blank=True)
    spf = models.JSONField(default=list, blank=True)
    dmarc = models.JSONField(default=list, blank=True)
    mx = models.JSONField(default=list, blank=True)
    dkim_selector1 = models.JSONField(default=list, blank=True)
    dkim_default = models.JSONField(default=list, blank=True)
    smtp_hosts = models.JSONField(default=list, blank=True)
    smtp_port_scan = models.JSONField(default=dict, blank=True)
    smtp_open_relay = models.JSONField(default=dict, blank=True)
    smtp_starttls = models.JSONField(default=dict, blank=True)
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Email Security - {self.domain}"
