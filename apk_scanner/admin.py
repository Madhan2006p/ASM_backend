from django.contrib import admin
from .models import APKFile, APKAnalysis

# Removed from admin UI per user request
# @admin.register(APKFile)
# class APKFileAdmin(admin.ModelAdmin):
#     list_display = ('original_name', 'file_size', 'status', 'md5_hash', 'uploaded_at')
#     list_filter = ('status',)
#     search_fields = ('original_name', 'md5_hash')

# @admin.register(APKAnalysis)
# class APKAnalysisAdmin(admin.ModelAdmin):
#     list_display = ('apk', 'package_name', 'version_name', 'severity', 'analyzed_at')
#     list_filter = ('severity',)
#     search_fields = ('package_name', 'apk__original_name')
