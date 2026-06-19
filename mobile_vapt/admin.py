from django.contrib import admin
from .models import MobileScan, MobileFinding, MobilePermission, SecurityScore


class MobileFindingInline(admin.TabularInline):
    model = MobileFinding
    extra = 0
    fields = ['severity', 'vulnerability', 'category', 'file_path']
    readonly_fields = ['severity', 'vulnerability', 'category', 'description', 'file_path']
    can_delete = False

@admin.register(MobileScan)
class MobileScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'file_name', 'app_name', 'status', 'uploaded_at']
    list_filter = ['status', 'source']
    search_fields = ['file_name', 'app_name', 'package_name']
    inlines = [MobileFindingInline]
    
    def save_model(self, request, obj, form, change):
        if not obj.file_name and obj.apk_file:
            import os
            obj.file_name = os.path.basename(obj.apk_file.name)
        if not obj.scan_hash and obj.apk_file:
            import hashlib
            obj.scan_hash = hashlib.md5(obj.apk_file.name.encode()).hexdigest()
        
        super().save_model(request, obj, form, change)
        
        if obj.apk_file and not obj.vt_scan_id:
            from .tasks import scan_apk_virustotal
            scan_apk_virustotal.delay(obj.id)


@admin.register(MobileFinding)
class MobileFindingAdmin(admin.ModelAdmin):
    list_display = ['vulnerability', 'severity', 'category', 'scan']
    list_filter = ['severity', 'category']
    search_fields = ['vulnerability', 'description']


@admin.register(MobilePermission)
class MobilePermissionAdmin(admin.ModelAdmin):
    list_display = ['permission_name', 'status', 'severity', 'scan']
    search_fields = ['permission_name']


@admin.register(SecurityScore)
class SecurityScoreAdmin(admin.ModelAdmin):
    list_display = ['category', 'score', 'max_score', 'scan']
