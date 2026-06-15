from django.contrib import admin
from .models import Target, Technology, Endpoint

@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ('domain', 'user', 'added_on', 'last_scanned')
    list_filter = ('user',)
    search_fields = ('domain', 'description')

@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = ('url', 'method', 'status_code', 'target', 'discovered_on')
    list_filter = ('method', 'target')
    search_fields = ('url',)

@admin.register(Technology)
class TechnologyAdmin(admin.ModelAdmin):
    list_display = ('name', 'version', 'category', 'target', 'detected_by', 'detected_at')
    list_filter = ('category', 'detected_by', 'target')
    search_fields = ('name', 'version', 'category', 'target__domain')
