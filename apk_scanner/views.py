import os
from rest_framework import viewsets, permissions, status, parsers
from rest_framework.response import Response
from rest_framework.decorators import action
from django.conf import settings

from authentication.permissions import (
    HasModulePermission,
    IsAuthenticatedAndOrgMember,
)

from .models import APKFile, APKAnalysis
from .serializers import APKFileSerializer, APKAnalysisSerializer, APKUploadSerializer
from .tasks import analyze_apk_file


class APKFileViewSet(viewsets.ModelViewSet):
    serializer_class = APKFileSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "apk_scanner"
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]

    queryset = APKFile.objects.all()

    @action(detail=False, methods=['post'], parser_classes=[parsers.MultiPartParser])
    def upload(self, request):
        serializer = APKUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        file_obj = request.FILES['file']
        original_name = file_obj.name

        if not original_name.endswith('.apk'):
            return Response({'error': 'Only .apk files are allowed'}, status=status.HTTP_400_BAD_REQUEST)

        apk = APKFile.objects.create(
            file=file_obj,
            original_name=original_name,
            file_size=file_obj.size,
        )

        analyze_apk_file.delay(apk.id)

        resp_serializer = APKFileSerializer(apk)
        return Response(resp_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'])
    def analysis(self, request, pk=None):
        apk = self.get_object()
        try:
            analysis = apk.analysis
            serializer = APKAnalysisSerializer(analysis)
            return Response(serializer.data)
        except APKAnalysis.DoesNotExist:
            return Response({'detail': 'Analysis not yet completed'}, status=status.HTTP_404_NOT_FOUND)
