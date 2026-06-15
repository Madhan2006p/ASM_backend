from rest_framework import viewsets, permissions, status
from rest_framework.response import Response

from authentication.permissions import (
    HasModulePermission,
    IsAuthenticatedAndOrgMember,
    get_user_org_id,
)

from .models import FuzzingQueue, FuzzingResult
from .serializers import FuzzingQueueSerializer, FuzzingResultSerializer
from .tasks import run_arjun



class FuzzingResultViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = FuzzingResultSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "fuzzing"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return FuzzingResult.objects.select_related('endpoint__target').filter(
            endpoint__target__user=self.request.user,
            endpoint__target__user__memberships__organization__org_id=org_id,
        )


class FuzzingQueueViewSet(viewsets.ModelViewSet):
    serializer_class = FuzzingQueueSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "fuzzing"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return FuzzingQueue.objects.select_related('endpoint__target').filter(
            endpoint__target__user=self.request.user,
            endpoint__target__user__memberships__organization__org_id=org_id,
        )

    def perform_create(self, serializer):
        queue = serializer.save()
        run_arjun.delay(queue.id)
