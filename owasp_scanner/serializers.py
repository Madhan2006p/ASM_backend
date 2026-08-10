"""
OWASP Scanner - DRF Serializers
=================================
"""
from __future__ import annotations

from rest_framework import serializers

from .models import (
    OWASPScanSession, OWASPFinding, DiscoveredAsset,
    CVERecord, ScannerLog
)


class OWASPScanSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = OWASPScanSession
        fields = [
            'id', 'target', 'target_url', 'status',
            'categories', 'scan_config',
            'progress_percent', 'current_phase', 'phases_completed',
            'total_findings', 'critical_count', 'high_count',
            'medium_count', 'low_count', 'info_count',
            'created_at', 'started_at', 'completed_at', 'duration_seconds',
            'celery_task_id', 'error_message',
            'report_json', 'report_html', 'report_pdf', 'report_csv',
        ]
        read_only_fields = ['id', 'created_at']


class StartScanSerializer(serializers.Serializer):
    target_id = serializers.IntegerField(required=False, allow_null=True)
    target_url = serializers.URLField(required=False, allow_blank=True, default='')
    categories = serializers.ListField(
        child=serializers.ChoiceField(choices=['A01', 'A02', 'A03', 'A04', 'A05',
                                               'A06', 'A07', 'A08', 'A09', 'A10']),
        required=False, default=list
    )
    scan_config = serializers.DictField(required=False, default=dict)

    def validate(self, attrs):
        if not attrs.get('target_id') and not attrs.get('target_url'):
            raise serializers.ValidationError("Either target_id or target_url is required.")
        return attrs


class OWASPFindingSerializer(serializers.ModelSerializer):
    owasp_category_display = serializers.CharField(
        source='get_owasp_category_display', read_only=True
    )

    class Meta:
        model = OWASPFinding
        fields = [
            'id', 'session', 'name', 'owasp_category', 'owasp_category_display',
            'owasp_name', 'cwe_id', 'capec_id', 'vulnerability_type',
            'severity', 'confidence', 'cvss_score', 'cvss_vector',
            'cve_ids', 'epss_score', 'epss_percentile',
            'in_cisa_kev', 'exploit_available', 'exploit_references',
            'affected_url', 'affected_param', 'affected_header',
            'http_request', 'http_response', 'evidence', 'proof',
            'description', 'risk_description', 'business_impact',
            'remediation', 'references',
            'detected_by', 'is_false_positive', 'is_verified',
            'false_positive_reason', 'raw_data', 'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class DiscoveredAssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = DiscoveredAsset
        fields = [
            'id', 'session', 'asset_type', 'url', 'method',
            'params', 'forms', 'status_code', 'content_type', 'discovered_at',
        ]


class CVERecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = CVERecord
        fields = '__all__'


class ScannerLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScannerLog
        fields = ['id', 'level', 'phase', 'message', 'timestamp']
