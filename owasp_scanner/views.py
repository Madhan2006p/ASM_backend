"""
OWASP Scanner - REST API Views
================================
Django REST Framework views for the OWASP scanner module.
Provides endpoints to start scans, check status, and retrieve reports.
"""
from __future__ import annotations

import logging
from typing import Any

from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.pagination import PageNumberPagination

from targets.models import Target
from .models import (
    OWASPScanSession, OWASPFinding, DiscoveredAsset,
    CVERecord, ScannerLog
)
from .serializers import (
    OWASPScanSessionSerializer, OWASPFindingSerializer,
    StartScanSerializer, DiscoveredAssetSerializer, ScannerLogSerializer
)

logger = logging.getLogger('scanner.views')


class StartScanView(APIView):
    """
    POST /api/owasp-scanner/start/
    Start a new OWASP Top 10 scan for a target.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = StartScanSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        target_id = data.get('target_id')
        target_url = data.get('target_url', '')
        categories = data.get('categories', [])
        scan_config = data.get('scan_config', {})

        # Get target from DB
        target = None
        if target_id:
            try:
                target = Target.objects.get(id=target_id)
                if not target_url:
                    target_url = f"https://{target.domain}"
            except Target.DoesNotExist:
                return Response({'error': 'Target not found'}, status=status.HTTP_404_NOT_FOUND)

        if not target_url:
            return Response({'error': 'target_url is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Create session
        session = OWASPScanSession.objects.create(
            target=target,
            target_url=target_url,
            status='PENDING',
            categories=categories,
            scan_config=scan_config,
        )

        # Launch scan in background thread for guaranteed automatic progression
        import threading
        from .tasks import execute_scan_sync

        def run_thread():
            try:
                execute_scan_sync(
                    session_id=str(session.id),
                    target_url=target_url,
                    categories=categories or None,
                )
            except Exception as e:
                logger.error("Background scan thread failed: %s", e)

        thread = threading.Thread(target=run_thread, daemon=True)
        thread.start()

        return Response(
            {
                'session_id': str(session.id),
                'status': 'RUNNING',
                'target_url': target_url,
                'message': 'OWASP Top 10 scan started automatically',
            },
            status=status.HTTP_201_CREATED
        )


class ScanSessionListView(ListAPIView):
    """
    GET /api/owasp-scanner/sessions/
    List all OWASP scan sessions.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = OWASPScanSessionSerializer
    pagination_class = None

    def get_queryset(self):
        qs = OWASPScanSession.objects.all()
        target_id = self.request.query_params.get('target_id')
        status_filter = self.request.query_params.get('status')
        if target_id:
            qs = qs.filter(target_id=target_id)
        if status_filter:
            qs = qs.filter(status=status_filter.upper())
        return qs.order_by('-created_at')


class ScanSessionDetailView(RetrieveAPIView):
    """
    GET /api/owasp-scanner/sessions/<uuid>/
    Get a specific scan session with summary.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = OWASPScanSessionSerializer
    queryset = OWASPScanSession.objects.all()
    lookup_field = 'id'


class ScanStatusView(APIView):
    """
    GET /api/owasp-scanner/sessions/<uuid>/status/
    Real-time scan status with progress.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, session_id: str) -> Response:
        try:
            session = OWASPScanSession.objects.get(id=session_id)
        except OWASPScanSession.DoesNotExist:
            return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response({
            'id': str(session.id),
            'session_id': str(session.id),
            'status': session.status,
            'progress_percent': session.progress_percent,
            'current_phase': session.current_phase,
            'phases_completed': session.phases_completed,
            'total_findings': session.total_findings,
            'severity_breakdown': {
                'critical': session.critical_count,
                'high': session.high_count,
                'medium': session.medium_count,
                'low': session.low_count,
                'info': session.info_count,
            },
            'started_at': session.started_at,
            'completed_at': session.completed_at,
            'duration_seconds': session.duration_seconds,
            'error_message': session.error_message,
        })


class CancelScanView(APIView):
    """
    POST /api/owasp-scanner/sessions/<uuid>/cancel/
    Cancel a running scan.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, session_id: str) -> Response:
        try:
            session = OWASPScanSession.objects.get(id=session_id)
        except OWASPScanSession.DoesNotExist:
            return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        if session.status not in ('PENDING', 'RUNNING'):
            return Response({'error': 'Scan is not running'}, status=status.HTTP_400_BAD_REQUEST)

        session.status = 'CANCELLED'
        session.completed_at = timezone.now()
        session.save()

        return Response({'message': 'Scan cancelled successfully'})


class FindingsListView(ListAPIView):
    """
    GET /api/owasp-scanner/sessions/<uuid>/findings/
    List findings for a specific scan session.
    Supports filtering by severity, owasp_category, and search.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = OWASPFindingSerializer
    pagination_class = None

    def get_queryset(self):
        session_id = self.kwargs.get('session_id')
        try:
            session = OWASPScanSession.objects.get(id=session_id)
        except OWASPScanSession.DoesNotExist:
            return OWASPFinding.objects.none()

        qs = session.findings.all()

        # Filters
        severity = self.request.query_params.get('severity')
        category = self.request.query_params.get('category')
        search = self.request.query_params.get('search')
        exploit_only = self.request.query_params.get('exploit_only')
        kev_only = self.request.query_params.get('kev_only')

        if severity:
            qs = qs.filter(severity=severity.upper())
        if category:
            qs = qs.filter(owasp_category=category.upper())
        if search:
            qs = qs.filter(name__icontains=search)
        if exploit_only and exploit_only.lower() == 'true':
            qs = qs.filter(exploit_available=True)
        if kev_only and kev_only.lower() == 'true':
            qs = qs.filter(in_cisa_kev=True)

        return qs.order_by(
            '-severity',  # Custom ordering by severity weight
            '-cvss_score',
        )


class FindingDetailView(RetrieveAPIView):
    """
    GET /api/owasp-scanner/findings/<uuid>/
    Get a specific finding with full detail.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = OWASPFindingSerializer
    queryset = OWASPFinding.objects.all()
    lookup_field = 'id'


class ScanReportView(APIView):
    """
    GET /api/owasp-scanner/sessions/<uuid>/report/
    Get the full scan report with all findings and statistics.
    Optionally accepts ?format=json|html|csv|pdf for report format.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, session_id: str) -> Response:
        try:
            session = OWASPScanSession.objects.get(id=session_id)
        except OWASPScanSession.DoesNotExist:
            return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        if session.status not in ('COMPLETED', 'RUNNING'):
            return Response(
                {'error': f'No report available. Scan status: {session.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Build report from DB
        findings = session.findings.all().order_by('-severity', '-cvss_score')

        by_category = {}
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        for finding in findings:
            cat = finding.owasp_category
            if cat not in by_category:
                by_category[cat] = {
                    'name': finding.get_owasp_category_display(),
                    'count': 0,
                    'findings': []
                }
            by_category[cat]['count'] += 1
            by_category[cat]['findings'].append(OWASPFindingSerializer(finding).data)
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        assets = session.assets.all()
        asset_by_type = {}
        for asset in assets:
            asset_by_type[asset.asset_type] = asset_by_type.get(asset.asset_type, 0) + 1

        report = {
            'summary': {
                'session_id': str(session.id),
                'target_url': session.target_url,
                'status': session.status,
                'started_at': session.started_at,
                'completed_at': session.completed_at,
                'duration_seconds': session.duration_seconds,
                'total_findings': session.total_findings,
                'severity_breakdown': severity_counts,
                'assets_discovered': assets.count(),
                'assets_by_type': asset_by_type,
            },
            'findings_by_category': by_category,
            'top_10_findings': OWASPFindingSerializer(
                findings.filter(severity__in=['CRITICAL', 'HIGH'])[:10], many=True
            ).data,
            'kev_findings': OWASPFindingSerializer(
                findings.filter(in_cisa_kev=True), many=True
            ).data,
            'exploit_available_findings': OWASPFindingSerializer(
                findings.filter(exploit_available=True), many=True
            ).data,
        }

        return Response(report)


class AssetsListView(ListAPIView):
    """
    GET /api/owasp-scanner/sessions/<uuid>/assets/
    List all discovered assets for a scan.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = DiscoveredAssetSerializer

    def get_queryset(self):
        session_id = self.kwargs.get('session_id')
        qs = DiscoveredAsset.objects.filter(session_id=session_id)
        asset_type = self.request.query_params.get('type')
        if asset_type:
            qs = qs.filter(asset_type=asset_type.upper())
        return qs.order_by('asset_type', 'url')


class ScanLogsView(ListAPIView):
    """
    GET /api/owasp-scanner/sessions/<uuid>/logs/
    Get the scanner activity logs for a session.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ScannerLogSerializer

    def get_queryset(self):
        session_id = self.kwargs.get('session_id')
        return ScannerLog.objects.filter(session_id=session_id).order_by('timestamp')


class MarkFalsePositiveView(APIView):
    """
    POST /api/owasp-scanner/findings/<uuid>/false-positive/
    Mark a finding as a false positive.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, finding_id: str) -> Response:
        try:
            finding = OWASPFinding.objects.get(id=finding_id)
        except OWASPFinding.DoesNotExist:
            return Response({'error': 'Finding not found'}, status=status.HTTP_404_NOT_FOUND)

        reason = request.data.get('reason', '')
        finding.is_false_positive = True
        finding.false_positive_reason = reason
        finding.save(update_fields=['is_false_positive', 'false_positive_reason'])

        return Response({'message': 'Finding marked as false positive', 'id': str(finding.id)})


class VerifyFindingView(APIView):
    """
    POST /api/owasp-scanner/findings/<uuid>/verify/
    Mark a finding as manually verified.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, finding_id: str) -> Response:
        try:
            finding = OWASPFinding.objects.get(id=finding_id)
        except OWASPFinding.DoesNotExist:
            return Response({'error': 'Finding not found'}, status=status.HTTP_404_NOT_FOUND)

        finding.is_verified = True
        finding.save(update_fields=['is_verified'])

        return Response({'message': 'Finding marked as verified', 'id': str(finding.id)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scanner_stats(request: Request) -> Response:
    """
    GET /api/owasp-scanner/stats/
    Overall OWASP scanner statistics across all scans.
    """
    total_sessions = OWASPScanSession.objects.count()
    completed = OWASPScanSession.objects.filter(status='COMPLETED').count()
    total_findings = OWASPFinding.objects.filter(is_false_positive=False).count()
    critical = OWASPFinding.objects.filter(severity='CRITICAL', is_false_positive=False).count()
    high = OWASPFinding.objects.filter(severity='HIGH', is_false_positive=False).count()
    kev_findings = OWASPFinding.objects.filter(in_cisa_kev=True, is_false_positive=False).count()
    exploit_findings = OWASPFinding.objects.filter(exploit_available=True, is_false_positive=False).count()

    # Most common vulnerability types
    from django.db.models import Count
    top_vulns = (
        OWASPFinding.objects
        .filter(is_false_positive=False)
        .values('vulnerability_type')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    top_categories = (
        OWASPFinding.objects
        .filter(is_false_positive=False)
        .values('owasp_category')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    return Response({
        'total_scans': total_sessions,
        'completed_scans': completed,
        'total_findings': total_findings,
        'critical_findings': critical,
        'high_findings': high,
        'cisa_kev_findings': kev_findings,
        'exploit_available_findings': exploit_findings,
        'top_vulnerability_types': list(top_vulns),
        'top_owasp_categories': list(top_categories),
    })
