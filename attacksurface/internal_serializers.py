from rest_framework import serializers
from .internal_models import InternalNetworkScan, InternalAsset

class InternalAssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = InternalAsset
        fields = '__all__'

class InternalNetworkScanSerializer(serializers.ModelSerializer):
    assets = InternalAssetSerializer(many=True, read_only=True)

    class Meta:
        model = InternalNetworkScan
        fields = '__all__'
