from django.contrib import admin
from .models import Scan, SSLResult, MonitorSchedule, DetectionResult

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'target', 'status', 'started_at', 'completed_at')
    list_filter = ('scan_type', 'status', 'target')
    search_fields = ('target__domain', 'scan_type')

@admin.register(SSLResult)
class SSLResultAdmin(admin.ModelAdmin):
    list_display = ('host', 'port', 'grade', 'scan', 'scanned_at')
    list_filter = ('grade', 'scan')
    search_fields = ('host',)

@admin.register(MonitorSchedule)
class MonitorScheduleAdmin(admin.ModelAdmin):
    list_display = ('name', 'target', 'frequency', 'is_active', 'last_run')
    list_filter = ('frequency', 'is_active', 'target')
    search_fields = ('name', 'target__domain')

@admin.register(DetectionResult)
class DetectionResultAdmin(admin.ModelAdmin):
    list_display = ('detection_type', 'target', 'status', 'acknowledged', 'detected_at')
    list_filter = ('detection_type', 'status', 'acknowledged', 'target')
    search_fields = ('detection_type', 'target__domain', 'details')
