from django.db import models
from targets.models import Target


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
