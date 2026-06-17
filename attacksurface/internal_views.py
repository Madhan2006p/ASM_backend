from rest_framework import viewsets, permissions
from .internal_models import InternalNetworkScan, InternalAsset
from .internal_serializers import InternalNetworkScanSerializer, InternalAssetSerializer
from authentication.permissions import IsAuthenticatedAndOrgMember, get_user_org_id

class InternalNetworkScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing internal network scans.
    """
    serializer_class = InternalNetworkScanSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        return InternalNetworkScan.objects.all().order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(org_id="1")

class InternalAssetViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing discovered internal assets.
    """
    serializer_class = InternalAssetSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        queryset = InternalAsset.objects.all()
        scan_id = self.request.query_params.get('scan')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        return queryset.order_by('-discovered_at')

    def perform_create(self, serializer):
        serializer.save(org_id="1")
