from django.db import models


class MobileScan(models.Model):
    app_name = models.CharField(max_length=255, blank=True, null=True)
    package_name = models.CharField(max_length=255, blank=True, null=True)
    file_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500, blank=True, null=True)
    scan_hash = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=50, default='uploaded')
    version_name = models.CharField(max_length=255, blank=True, null=True)
    score = models.CharField(max_length=50, blank=True, null=True)
    source = models.CharField(max_length=50, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.file_name} - {self.status}"


class MobileFinding(models.Model):
    scan = models.ForeignKey(MobileScan, on_delete=models.CASCADE, related_name='findings')
    vulnerability = models.CharField(max_length=500)
    severity = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=200, blank=True, null=True)
    file_path = models.CharField(max_length=500, blank=True, null=True)
    line_number = models.IntegerField(blank=True, null=True)
    recommendation = models.TextField(blank=True, null=True)
    risk = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-severity']

    def __str__(self):
        return f"{self.vulnerability} - {self.severity}"


class MobilePermission(models.Model):
    scan = models.ForeignKey(MobileScan, on_delete=models.CASCADE, related_name='permissions')
    permission_name = models.CharField(max_length=500)
    status = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.permission_name


class SecurityScore(models.Model):
    scan = models.ForeignKey(MobileScan, on_delete=models.CASCADE, related_name='scores')
    category = models.CharField(max_length=200)
    score = models.IntegerField(default=0)
    max_score = models.IntegerField(default=100)

    def __str__(self):
        return f"{self.category} - {self.score}/{self.max_score}"
