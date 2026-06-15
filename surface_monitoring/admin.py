from django.contrib import admin

from .models import GitHubRepository, RepoScan, SurfaceMonitorConfig


@admin.register(SurfaceMonitorConfig)
class SurfaceMonitorConfigAdmin(admin.ModelAdmin):
    list_display = ('keyword', 'is_active', 'interval_minutes', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('keyword',)


@admin.register(GitHubRepository)
class GitHubRepositoryAdmin(admin.ModelAdmin):
    list_display = (
        'full_name', 'owner', 'visibility', 'language', 'stars',
        'hardcoded_credentials_count', 'scanned_files_count', 'status',
    )
    list_filter = ('visibility', 'language', 'status')
    search_fields = ('full_name', 'owner', 'name', 'description')
    readonly_fields = (
        'hardcoded_credentials_count', 'scanned_files_count',
        'last_scanned_at', 'discovered_at',
    )


@admin.register(RepoScan)
class RepoScanAdmin(admin.ModelAdmin):
    list_display = (
        'repository', 'status', 'hardcoded_credentials_count',
        'scanned_files_count', 'started_at', 'completed_at',
    )
    list_filter = ('status',)
    search_fields = ('repository__full_name',)
