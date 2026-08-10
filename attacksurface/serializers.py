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
    ports = serializers.SerializerMethodField()

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
            "location",
            "screenshot_url",
            "waf",
            "cdn",
            "created_at",
            "updated_at",
            "created_date",
            "updated_date",
        ]

    def get_ports(self, obj):
        from .models import PortResult
        port_result = PortResult.objects.filter(scan=obj.scan, domain=obj.domain).first()
        raw_ports = port_result.ports if (port_result and port_result.ports) else obj.ports
        
        formatted_ports = []
        if isinstance(raw_ports, list):
            for p in raw_ports:
                if isinstance(p, dict):
                    formatted_ports.append(f"{p.get('port', '')}/{p.get('service', 'unknown')}")
                else:
                    formatted_ports.append(str(p))
        return formatted_ports


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
            # Content-based classification (computed by the analysis engine)
            "category",
            "risk",
            "access_status",
            "is_sensitive",
            "sensitive_matches",
            "title",
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
            "cvss_score",
            "finding",
            "description",
            "remediation",
            "reference",
            "template_id",
            "source_tool",
            "owasp_category",
            "owasp_rank",
            "confidence",
            "finding_status",
            "evidence",
            "discovered_at",
        ]


class SSLResultSerializer(serializers.ModelSerializer):
    """
    SSL/TLS certificate + protocol-attack findings.

    ``findings`` surfaces the SSL-related VulnerabilityResult rows produced by
    the audit engine (named attacks like BEAST/POODLE/Lucky13/RC4/3DES, weak
    ciphers, deprecated TLS, untrusted certs, Heartbleed) so the certificates
    UI can render a dedicated attacks table/chart.
    """

    findings = serializers.SerializerMethodField()

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
            "findings",
        ]

    def get_findings(self, obj):
        sub = (obj.subdomain or "").strip()
        dom = (obj.domain or "").strip()

        # Prefer the prefetched per-scan SSL findings (added by
        # SSLResultListView.get_queryset) to avoid N+1 queries.
        prefetched = getattr(obj, "_prefetched_objects_cache", {}).get("vulnerabilities")
        if prefetched is not None:
            ssl_vulns = [v for v in prefetched if sub and v.subdomain == sub or (not sub and v.subdomain == dom)]
        else:
            qs = VulnerabilityResult.objects.filter(scan=obj.scan)
            if sub:
                # Exact subdomain match (the scanner stores SSL vulns under the
                # scanned host, e.g. app.example.com).
                qs = qs.filter(subdomain=sub)
            else:
                # No subdomain recorded on the SSL row (fallback-created rows
                # have only `domain` set) -> match by domain so findings are not lost.
                if dom:
                    qs = qs.filter(subdomain=dom)
            ssl_vulns = list(qs)

        return [
            {
                "vulnerability_id": v.vulnerability_id,
                "severity": v.severity,
                "cve": v.cve or "",
                "cwe": v.cwe or "",
                "finding": v.finding or "",
                "description": v.description or "",
                "remediation": v.remediation or "",
                "template_id": v.template_id or "",
                "finding_status": v.finding_status or "",
                "confidence": v.confidence,
                "evidence": v.evidence or "",
            }
            for v in ssl_vulns
        ]


class EmailSecurityResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailSecurityResult
        fields = [
            "id",
            "domain",
            "spf",
            "dmarc",
            "mx",
            "dkim_default",
            "dkim_selector1",
            "bimi",
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
            "error_message",
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
            "nuclei_phase",
            "nuclei_found",
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
