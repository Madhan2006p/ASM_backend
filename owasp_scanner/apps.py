"""
OWASP Scanner - App Config
"""
from django.apps import AppConfig


class OwaspScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'owasp_scanner'
    verbose_name = 'OWASP Top 10 Vulnerability Scanner'
