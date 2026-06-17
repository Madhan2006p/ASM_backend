from rest_framework import serializers
from .models import ReconScan, ToolOutput, DiscoveredDomain, ReconEndpoint


class ReconScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReconScan
        fields = ["id", "target", "status", "progress", "created_at"]


class ToolOutputSerializer(serializers.ModelSerializer):
    class Meta:
        model = ToolOutput
        fields = ["id", "scan", "tool_name", "parsed_output", "created_at"]


class DiscoveredDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = DiscoveredDomain
        fields = ["id", "root_domain", "subdomain", "source", "created_at"]


class ReconEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReconEndpoint
        fields = ["id", "scan", "url", "source", "method", "status_code", "has_params", "created_at"]
