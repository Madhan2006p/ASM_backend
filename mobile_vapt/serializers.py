from rest_framework import serializers
from .models import MobileScan, MobileFinding, MobilePermission, SecurityScore


class MobileScanSerializer(serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()

    class Meta:
        model = MobileScan
        fields = '__all__'

    def get_findings_count(self, obj):
        return obj.findings.count()


class MobileFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = MobileFinding
        fields = '__all__'


class MobilePermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = MobilePermission
        fields = '__all__'


class SecurityScoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityScore
        fields = '__all__'


class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField()

    class Meta:
        fields = ['file']


class DashboardSerializer(serializers.Serializer):
    total_scans = serializers.IntegerField()
    total_findings = serializers.IntegerField()
    critical = serializers.IntegerField()
    high = serializers.IntegerField()
    medium = serializers.IntegerField()
    low = serializers.IntegerField()
    info = serializers.IntegerField()
    top_vulnerabilities = serializers.ListField(child=serializers.DictField())
    severity_distribution = serializers.DictField()
    category_distribution = serializers.DictField()
