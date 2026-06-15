from rest_framework import serializers
from .models import Target, Endpoint

class EndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint
        fields = '__all__'

class TargetSerializer(serializers.ModelSerializer):
    endpoints = EndpointSerializer(many=True, read_only=True)
    
    class Meta:
        model = Target
        fields = '__all__'
        read_only_fields = ('user', 'added_on', 'last_scanned')
