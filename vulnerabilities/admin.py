from django.contrib import admin
from .models import Vulnerability

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('title', 'cve_id', 'severity', 'cvss_score', 'target', 'source_tool', 'is_resolved', 'discovered_on')
    list_filter = ('severity', 'source_tool', 'is_resolved', 'target')
    search_fields = ('title', 'cve_id', 'cwe_id', 'description', 'target__domain')

