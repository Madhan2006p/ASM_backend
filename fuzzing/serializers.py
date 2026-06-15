from rest_framework import serializers
from .models import FuzzingResult, FuzzingQueue

class FuzzingResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = FuzzingResult
        fields = '__all__'

class FuzzingQueueSerializer(serializers.ModelSerializer):
    class Meta:
        model = FuzzingQueue
        fields = '__all__'
        read_only_fields = ('status', 'celery_task_id', 'started_at', 'completed_at')
