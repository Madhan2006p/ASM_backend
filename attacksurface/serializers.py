from rest_framework import serializers

from .models import (
    AttackSurfaceScan,
    DirectoryResult,
    EmailSecurityResult,
    EndpointResult,
    MonitoredDomain,
    PortResult,
    SSLResult,
    SubdomainResult,
    TechnologyResult,
    VulnerabilityResult,
)


class SubdomainResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubdomainResult
        fields = [
            "id",
            "domain",
            "status",
            "title",
            "technologies",
            "ip",
            "ports",
            "dns_records",
            "vulnerabilities_count",
            "waf",
            "cdn",
            "created_at",
            "updated_at",
        ]


class EndpointResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = EndpointResult
        fields = [
            "id",
            "http_url",
            "subdomain_name",
            "http_status",
            "content_type",
            "content_length",
            "title",
            "is_alive",
            "technologies",
            "threat_count",
            "method",
            "discovered_at",
            "last_scan",
        ]


class PortResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = PortResult
        fields = [
            "id",
            "domain",
            "ports",
            "created_at",
            "updated_at",
        ]


class DirectoryResultSerializer(serializers.ModelSerializer):
    discovered_date = serializers.DateTimeField(source="directories_created", read_only=True)

    class Meta:
        model = DirectoryResult
        fields = [
            "id",
            "url",
            "subdomain_name",
            "content_type",
            "content_details",
            "status",
            "directories_created",
            "discovered_date",
            "created",
            "updated",
        ]


class TechnologyResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = TechnologyResult
        fields = [
            "id",
            "domain",
            "technologies",
            "created_at",
            "updated_at",
        ]


class VulnerabilityResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityResult
        fields = [
            "id",
            "vulnerability_id",
            "domain",
            "subdomain",
            "severity",
            "cve",
            "cwe",
            "finding",
            "description",
            "remediation",
            "reference",
            "template_id",
            "source_tool",
            "discovered_at",
        ]


class SSLResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSLResult
        fields = [
            "id",
            "domain",
            "subdomain",
            "ip",
            "rdns",
            "ssl_grade",
            "issuer_name",
            "expiry_date",
            "purchase_date",
            "location",
            "cipher_suite",
            "is_trusted",
            "domain_aligned",
            "is_shadow_it",
            "ip_count",
            "dns_count",
            "created_at",
            "updated_at",
        ]


class EmailSecurityResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailSecurityResult
        fields = [
            "id",
            "domain",
            "root_txt",
            "spf",
            "dmarc",
            "mx",
            "dkim_selector1",
            "dkim_default",
            "smtp_hosts",
            "smtp_port_scan",
            "smtp_open_relay",
            "smtp_starttls",
            "created_at",
        ]


class AttackSurfaceScanSerializer(serializers.ModelSerializer):
    vulnerability_count = serializers.SerializerMethodField()
    subdomain_count = serializers.SerializerMethodField()
    endpoint_count = serializers.SerializerMethodField()
    directory_count = serializers.SerializerMethodField()
    ssl_count = serializers.SerializerMethodField()

    class Meta:
        model = AttackSurfaceScan
        fields = [
            "id",
            "target",
            "status",
            "progress",
            "org_id",
            "created_at",
            "updated_at",
            "subdomains_done",
            "endpoints_done",
            "ports_done",
            "technologies_done",
            "vulnerabilities_done",
            "ssl_done",
            "email_done",
            "directories_done",
            "malware_done",
            "vuln_scan_phase",
            "vulnerability_count",
            "subdomain_count",
            "endpoint_count",
            "directory_count",
            "ssl_count",
        ]

    def get_vulnerability_count(self, obj):
        return VulnerabilityResult.objects.filter(scan=obj).count()

    def get_subdomain_count(self, obj):
        return SubdomainResult.objects.filter(scan=obj).count()

    def get_endpoint_count(self, obj):
        return EndpointResult.objects.filter(scan=obj).count()

    def get_directory_count(self, obj):
        return DirectoryResult.objects.filter(scan=obj).count()

    def get_ssl_count(self, obj):
        return SSLResult.objects.filter(scan=obj).count()


class MonitoredDomainSerializer(serializers.ModelSerializer):
    latest_scan_id = serializers.SerializerMethodField()

    class Meta:
        model = MonitoredDomain
        fields = [
            "id",
            "domain",
            "org_id",
            "morning_time",
            "night_time",
            "morning_enabled",
            "night_enabled",
            "auto_scan_on_add",
            "last_morning_scan_at",
            "last_night_scan_at",
            "created_at",
            "updated_at",
            "latest_scan_id",
        ]

    def get_latest_scan_id(self, obj):
        scan = AttackSurfaceScan.objects.filter(
            target=obj.domain, org_id=obj.org_id
        ).order_by("-created_at").first()
        return scan.id if scan else None
