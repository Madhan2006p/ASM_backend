from rest_framework import serializers
from .models import Scan, SSLResult, MonitorSchedule, DetectionResult

class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = '__all__'
        read_only_fields = ('status', 'celery_task_id', 'started_at', 'completed_at', 'result_file')

class SSLResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSLResult
        fields = '__all__'
        read_only_fields = ('scanned_at',)

class MonitorScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = MonitorSchedule
        fields = '__all__'
        read_only_fields = ('last_run', 'next_run', 'created_at')

class DetectionResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionResult
        fields = '__all__'
        read_only_fields = ('detected_at',)
