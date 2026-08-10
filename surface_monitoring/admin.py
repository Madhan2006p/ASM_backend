from django.contrib import admin
from .models import SpiderfootScan, SpiderfootResult

@admin.register(SpiderfootScan)
class SpiderfootScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'status', 'org_id', 'created_at', 'completed_at')
    list_filter = ('status', 'org_id')
    search_fields = ('target',)

@admin.register(SpiderfootResult)
class SpiderfootResultAdmin(admin.ModelAdmin):
    list_display = ('scan', 'data_type', 'data_value', 'module', 'source', 'created_at')
    list_filter = ('data_type', 'module')
    search_fields = ('data_value', 'source')
