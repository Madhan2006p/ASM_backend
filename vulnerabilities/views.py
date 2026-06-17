from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action

from authentication.permissions import (
    HasModulePermission,
    IsAuthenticatedAndOrgMember,
    get_user_org_id,
    user_has_module_permission,
)

from .models import Vulnerability
from .serializers import VulnerabilitySerializer
from scans.models import Scan



class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "vulnerabilities"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return Vulnerability.objects.select_related('target').filter(
            target__user=self.request.user,
            target__user__memberships__organization__org_id=org_id,
        )

    @action(detail=False, methods=['get'])
    def by_scan(self, request):
        """Return vulnerabilities for a given scan ID, matched by target + source_tool."""
        if not user_has_module_permission(request.user, "vulnerabilities"):
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id query parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

        org_id = get_user_org_id(request)

        try:
            scan = Scan.objects.select_related('target').get(
                id=scan_id,
                target__user=request.user,
                target__user__memberships__organization__org_id=org_id,
            )
        except Scan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

        vulns = Vulnerability.objects.filter(
            target=scan.target,
            source_tool__icontains=scan.scan_type,
        ).select_related('target')

        serializer = self.get_serializer(vulns, many=True)
        return Response({
            'scan': {
                'id': scan.id,
                'target_domain': scan.target.domain,
                'target_id': scan.target.id,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'started_at': scan.started_at,
                'completed_at': scan.completed_at,
                'result_file': scan.result_file,
            },
            'vulnerabilities': serializer.data,
        })
