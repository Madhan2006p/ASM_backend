from django.db import models
from django.contrib.auth.models import User


class Target(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    org_id = models.CharField(max_length=50, db_index=True, default="1")
    domain = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    last_scanned = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.domain

    class Meta:
        indexes = [
            models.Index(fields=["org_id", "domain"]),
        ]

class Endpoint(models.Model):
    target = models.ForeignKey(Target, related_name='endpoints', on_delete=models.CASCADE)
    url = models.URLField(max_length=2048)
    method = models.CharField(max_length=10, default='GET')
    status_code = models.IntegerField(null=True, blank=True)
    technology = models.CharField(max_length=100, blank=True) # REST, GraphQL, etc.
    discovered_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.method} {self.url}"

class Technology(models.Model):
    target = models.ForeignKey(Target, related_name='technologies', on_delete=models.CASCADE)
    endpoint = models.ForeignKey(Endpoint, related_name='endpoint_technologies', on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100) # e.g., WordPress, Nginx, jQuery
    version = models.CharField(max_length=50, blank=True, null=True)
    category = models.CharField(max_length=100, blank=True, null=True) # e.g., CMS, Web Server, JS Library
    detected_by = models.CharField(max_length=50, default='Wappalyzer')
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Technologies"

    def __str__(self):
        version_str = f" v{self.version}" if self.version else ""
        return f"{self.name}{version_str} on {self.target.domain}"

