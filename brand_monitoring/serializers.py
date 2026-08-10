from rest_framework import serializers

from .models import BrandMonitorTarget, VirusTotalReport, SuspiciousDomainReport, PhishingDomainReport, ImpersonatingScan, ImpersonatingAccountResult, AntiPhishingScan


class BrandMonitorTargetSerializer(serializers.ModelSerializer):
    latest_report = serializers.SerializerMethodField()
    report_count = serializers.SerializerMethodField()

    class Meta:
        model = BrandMonitorTarget
        fields = [
            'id', 'domain', 'brand_name', 'is_active', 'interval_minutes',
            'status', 'last_checked_at', 'org_id', 'created_at', 'updated_at',
            'latest_report', 'report_count',
        ]
        read_only_fields = ('org_id', 'created_at', 'updated_at', 'status', 'last_checked_at')

    def get_latest_report(self, obj):
        report = obj.reports.order_by('-checked_at').first()
        if report:
            return {
                'id': report.id,
                'malicious': report.malicious,
                'suspicious': report.suspicious,
                'harmless': report.harmless,
                'undetected': report.undetected,
                'timeout': report.timeout,
                'total_engines': report.total_engines,
                'reputation_score': report.reputation_score,
                'checked_at': report.checked_at,
            }
        return None

    def get_report_count(self, obj):
        return obj.reports.count()


class VirusTotalReportSerializer(serializers.ModelSerializer):
    target_domain = serializers.CharField(source='target.domain', read_only=True)

    class Meta:
        model = VirusTotalReport
        fields = [
            'id', 'target', 'target_domain', 'domain',
            'malicious', 'suspicious', 'harmless', 'undetected', 'timeout',
            'total_engines', 'reputation_score', 'categories', 'tags',
            'raw_response', 'error_message', 'org_id', 'checked_at',
        ]
        read_only_fields = [
            'id', 'target', 'target_domain', 'domain',
            'malicious', 'suspicious', 'harmless', 'undetected', 'timeout',
            'total_engines', 'reputation_score', 'categories', 'tags',
            'raw_response', 'error_message', 'org_id', 'checked_at',
        ]


class BrandMonitorDashboardSerializer(serializers.Serializer):
    total_targets = serializers.IntegerField()
    total_reports = serializers.IntegerField()
    active_targets = serializers.IntegerField()
    total_malicious = serializers.IntegerField()
    total_suspicious = serializers.IntegerField()
    
    # New fields needed by frontend
    total_suspicious_domains = serializers.IntegerField(required=False, default=0)
    total_phishing_domains = serializers.IntegerField(required=False, default=0)
    total_impersonations = serializers.IntegerField(required=False, default=0)
    active_alerts = serializers.IntegerField(required=False, default=0)
    
    org_name = serializers.CharField(required=False, default="")
    latest_reports = serializers.ListField(child=VirusTotalReportSerializer(), required=False)
    targets_by_status = serializers.DictField(child=serializers.IntegerField())


class SuspiciousDomainReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuspiciousDomainReport
        fields = [
            'id', 'domain', 'apex_domain', 'resolution_status', 'status', 'whois_raw', 'dns_a', 'dns_mx',
            'dns_ns', 'dns_txt', 'dnsrecon_raw', 'reverse_dns', 'screenshot_url', 'registrar', 'whois_created',
            'org_id', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'apex_domain', 'resolution_status', 'status', 'whois_raw', 'dns_a', 'dns_mx',
            'dns_ns', 'dns_txt', 'dnsrecon_raw', 'reverse_dns', 'screenshot_url', 'registrar', 'whois_created',
            'org_id', 'created_at', 'updated_at'
        ]


class PhishingDomainReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhishingDomainReport
        fields = [
            'id', 'target', 'domain', 'apex_domain', 'status', 'variation_type',
            'is_active', 'dns_a', 'dns_mx', 'dns_ns', 'urlscan_status', 'urlscan_score',
            'urlscan_id', 'urlscan_raw', 'page_title', 'technologies', 'server_header',
            'screenshot_url', 'org_id', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'target', 'domain', 'apex_domain', 'status', 'variation_type',
            'is_active', 'dns_a', 'dns_mx', 'dns_ns', 'urlscan_status', 'urlscan_score',
            'urlscan_id', 'urlscan_raw', 'page_title', 'technologies', 'server_header',
            'screenshot_url', 'org_id', 'created_at', 'updated_at'
        ]



class ImpersonatingAccountResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ImpersonatingAccountResult
        fields = [
            'id', 'scan', 'org_id', 'platform', 'platform_label',
            'username', 'full_name', 'profile_url',
            'followers', 'following', 'is_private',
            'action_status', 'action_team', 'source',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'scan', 'org_id', 'platform', 'platform_label',
            'username', 'full_name', 'profile_url',
            'followers', 'following', 'is_private', 'source',
            'created_at', 'updated_at',
        ]


class ImpersonatingScanSerializer(serializers.ModelSerializer):
    results = ImpersonatingAccountResultSerializer(many=True, read_only=True)
    result_count = serializers.SerializerMethodField()

    class Meta:
        model = ImpersonatingScan
        fields = [
            'id', 'username', 'brand_domain', 'org_name', 'status',
            'org_id', 'created_at', 'completed_at',
            'result_count', 'results',
        ]
        read_only_fields = ['id', 'status', 'org_id', 'created_at', 'completed_at', 'result_count', 'results']

    def get_result_count(self, obj):
        return obj.results.count()

class AntiPhishingScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = AntiPhishingScan
        fields = '__all__'
        read_only_fields = ['id', 'status', 'org_id', 'created_at', 'completed_at']
