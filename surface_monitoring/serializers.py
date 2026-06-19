from rest_framework import serializers
from .models import SpiderfootScan, SpiderfootResult

class SpiderfootScanSerializer(serializers.ModelSerializer):
    results_count = serializers.SerializerMethodField()

    class Meta:
        model = SpiderfootScan
        fields = [
            'id', 'target', 'status', 'org_id', 'created_at', 
            'completed_at', 'results_count'
        ]
        read_only_fields = ('org_id', 'created_at', 'completed_at', 'status')

    def get_results_count(self, obj):
        return obj.results.count()


class SpiderfootResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = SpiderfootResult
        fields = [
            'id', 'scan', 'data_type', 'data_value', 'module', 
            'source', 'created_at'
        ]
        read_only_fields = ('id', 'created_at')
