from django.db import models

class SpiderfootScan(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Spiderfoot Scan"
        verbose_name_plural = "Spiderfoot Scans"

    def __str__(self):
        return f"{self.target} - {self.status}"


class SpiderfootResult(models.Model):
    scan = models.ForeignKey(SpiderfootScan, on_delete=models.CASCADE, related_name='results')
    data_type = models.CharField(max_length=255)
    data_value = models.TextField()
    module = models.CharField(max_length=255)
    source = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Spiderfoot Result"
        verbose_name_plural = "Spiderfoot Results"

    def __str__(self):
        return f"{self.data_type}: {self.data_value[:50]}"
