from django.db import models
from targets.models import Endpoint

class FuzzingResult(models.Model):
    endpoint = models.ForeignKey(Endpoint, related_name='fuzzing_results', on_delete=models.CASCADE)
    parameter = models.CharField(max_length=255)
    method = models.CharField(max_length=10) # GET, POST, JSON
    discovered_on = models.DateTimeField(auto_now_add=True)
    is_vulnerable = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.parameter} on {self.endpoint.url}"

class FuzzingQueue(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    )

    endpoint = models.ForeignKey(Endpoint, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    method = models.CharField(max_length=10, default='GET')
    auth_header = models.CharField(max_length=512, blank=True, null=True)
    auth_cookie = models.CharField(max_length=512, blank=True, null=True)
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Queue {self.id} for {self.endpoint.url}"
