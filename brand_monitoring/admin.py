from django.contrib import admin

from .models import BrandMonitorTarget, VirusTotalReport, SuspiciousDomainReport, PhishingDomainReport


@admin.register(BrandMonitorTarget)
class BrandMonitorTargetAdmin(admin.ModelAdmin):
    list_display = ('domain', 'brand_name', 'is_active', 'status', 'last_checked_at', 'created_at', 'org_id')
    list_filter = ('is_active', 'status', 'org_id')
    search_fields = ('domain', 'brand_name')
    readonly_fields = ('status', 'last_checked_at')


@admin.register(VirusTotalReport)
class VirusTotalReportAdmin(admin.ModelAdmin):
    list_display = (
        'domain', 'malicious', 'suspicious', 'harmless',
        'undetected', 'total_engines', 'org_id', 'checked_at',
    )
    list_filter = ('checked_at', 'org_id')
    search_fields = ('domain',)
    list_select_related = ('target',)
    readonly_fields = (
        'malicious', 'suspicious', 'harmless', 'undetected',
        'timeout', 'total_engines', 'reputation_score', 'org_id',
    )


@admin.register(SuspiciousDomainReport)
class SuspiciousDomainReportAdmin(admin.ModelAdmin):
    list_display = ('domain', 'apex_domain', 'resolution_status', 'status', 'registrar', 'whois_created', 'created_at', 'org_id')
    list_filter = ('resolution_status', 'status', 'org_id', 'created_at')
    search_fields = ('domain', 'apex_domain', 'registrar')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(PhishingDomainReport)
class PhishingDomainReportAdmin(admin.ModelAdmin):
    list_display = ('domain', 'apex_domain', 'variation_type', 'is_active', 'status', 'urlscan_status', 'urlscan_score', 'created_at', 'org_id')
    list_filter = ('is_active', 'status', 'urlscan_status', 'org_id', 'created_at')
    search_fields = ('domain', 'apex_domain', 'variation_type')
    readonly_fields = ('created_at', 'updated_at')

