from django.db import models

class Finding(models.Model):
    defectdojo_finding_id = models.IntegerField(primary_key=True, db_column='defectdojo_finding_id')
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=50)
    cve = models.CharField(max_length=255, null=True, blank=True)
    cwe = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    mitigation = models.TextField(null=True, blank=True)
    endpoint = models.CharField(max_length=255, null=True, blank=True)
    active = models.BooleanField(default=True)
    date_found = models.DateTimeField()
    risk_score = models.IntegerField(null=True, blank=True)
    affected_asset = models.CharField(max_length=255, db_column='affected_asset', null=True, blank=True)
    status = models.CharField(max_length=50)
    detection_time = models.CharField(max_length=100)
    source_tool = models.CharField(max_length=50, db_column='source_tool')

    class Meta:
        db_table = 'findings'
        
    def __str__(self):
        return f"{self.title} ({self.severity})"
