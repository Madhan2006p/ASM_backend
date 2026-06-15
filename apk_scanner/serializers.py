from rest_framework import serializers
from .models import APKFile, APKAnalysis


class APKFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = APKFile
        fields = '__all__'
        read_only_fields = ('original_name', 'file_size', 'md5_hash', 'status', 'celery_task_id', 'uploaded_at')


class APKAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = APKAnalysis
        fields = '__all__'


class APKUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
