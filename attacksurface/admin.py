import threading
from django.contrib import admin
from django.contrib import messages
from .views import run_full_scan
from .models import (
    AttackSurfaceScan,
    SubdomainResult,
    EndpointResult,
    PortResult,
    DirectoryResult,
    TechnologyResult,
    VulnerabilityResult,
    SSLResult,
    EmailSecurityResult,
)

@admin.action(description='Trigger full attack surface scan for selected targets')
def trigger_scan_action(modeladmin, request, queryset):
    count = 0
    for scan in queryset:
        if scan.status not in ["running", "pending"]:
            scan.status = "pending"
            scan.save()
            thread = threading.Thread(target=run_full_scan, args=(scan,), daemon=True)
            thread.start()
            count += 1
    
    modeladmin.message_user(request, f"Successfully triggered {count} scans in the background.", messages.SUCCESS)

class AttackSurfaceScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'target', 'org_id', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'org_id')
    search_fields = ('target', 'org_id')
    actions = [trigger_scan_action]

admin.site.register(AttackSurfaceScan, AttackSurfaceScanAdmin)
admin.site.register(SubdomainResult)
admin.site.register(EndpointResult)
admin.site.register(PortResult)
admin.site.register(DirectoryResult)
admin.site.register(TechnologyResult)
admin.site.register(VulnerabilityResult)
admin.site.register(SSLResult)
admin.site.register(EmailSecurityResult)
