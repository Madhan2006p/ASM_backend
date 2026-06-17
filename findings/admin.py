from django.contrib import admin
from .models import Finding

@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'endpoint', 'cve', 'cwe', 'date_found')
    list_filter = ('severity', 'status', 'source_tool')
    search_fields = ('title', 'endpoint', 'cve')
    
    # Make all fields read-only since findings are managed by the VAPT pipeline
    readonly_fields = [f.name for f in Finding._meta.get_fields()]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
