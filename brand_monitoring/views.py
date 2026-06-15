from django.db.models import Count, Sum
from django.utils import timezone

from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from authentication.permissions import (
    IsAuthenticatedAndOrgMember,
    IsOrgAdmin,
    get_user_org_id,
)

from .models import BrandMonitorTarget, VirusTotalReport, SuspiciousDomainReport, PhishingDomainReport, ImpersonatingScan, ImpersonatingAccountResult
from .serializers import (
    BrandMonitorTargetSerializer,
    VirusTotalReportSerializer,
    BrandMonitorDashboardSerializer,
    SuspiciousDomainReportSerializer,
    PhishingDomainReportSerializer,
    ImpersonatingScanSerializer,
    ImpersonatingAccountResultSerializer,
)
from .tasks import check_domain_virustotal, analyze_suspicious_domain_task, analyze_phishing_domain_task
from authentication.models import Organization


class BrandMonitorTargetViewSet(viewsets.ModelViewSet):
    """
    CRUD for brand monitoring targets (domains to check via VirusTotal).
    """
    serializer_class = BrandMonitorTargetSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = "brand_monitoring"

    def _sync_targets(self, org_id):
        try:
            from attacksurface.models import MonitoredDomain, AttackSurfaceScan
            # Get list of domains in MonitoredDomain for this org
            monitored_domains = set(
                MonitoredDomain.objects.filter(org_id=org_id)
                .values_list('domain', flat=True)
            )
            # Add domains from AttackSurfaceScan for this org
            scanned_domains = set(
                AttackSurfaceScan.objects.filter(org_id=org_id)
                .values_list('target', flat=True)
            )
            all_domains = monitored_domains | scanned_domains
            
            # Get existing BrandMonitorTarget domains
            existing_targets = BrandMonitorTarget.objects.filter(org_id=org_id)
            existing_domains = set(existing_targets.values_list('domain', flat=True))
            
            # Targets to create
            to_create = all_domains - existing_domains
            for domain in to_create:
                BrandMonitorTarget.objects.create(
                    domain=domain,
                    brand_name=domain.split('.')[0].capitalize(),
                    is_active=True,
                    status='active',
                    org_id=org_id
                )
                
            # Targets to delete (no longer monitored or scanned)
            to_delete = existing_domains - all_domains
            if to_delete:
                BrandMonitorTarget.objects.filter(org_id=org_id, domain__in=to_delete).delete()
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error syncing BrandMonitorTarget with MonitoredDomain: {e}")

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        self._sync_targets(org_id)
        return BrandMonitorTarget.objects.filter(org_id=org_id).prefetch_related('reports')

    def create(self, request, *args, **kwargs):
        return Response(
            {"detail": "Adding domains must be done from the main Dashboard."},
            status=status.HTTP_400_BAD_REQUEST
        )

    def destroy(self, request, *args, **kwargs):
        return Response(
            {"detail": "Deleting domains must be done from the main Dashboard."},
            status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, IsOrgAdmin])
    def scan(self, request, pk=None):
        """
        Trigger a VirusTotal domain report check for this target.
        Admin-only to prevent API quota abuse.
        """
        target = self.get_object()
        task = check_domain_virustotal.delay(target_id=target.id)
        return Response({
            'task_id': task.id,
            'domain': target.domain,
            'status': 'vt_check_queued',
        }, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, IsOrgAdmin])
    def scan_all(self, request):
        """
        Trigger VirusTotal check on all active targets.
        Admin-only to prevent API quota abuse.
        """
        org_id = get_user_org_id(self.request)
        self._sync_targets(org_id)
        targets = BrandMonitorTarget.objects.filter(org_id=org_id, is_active=True)
        task_ids = []
        for target in targets:
            task = check_domain_virustotal.delay(target_id=target.id)
            task_ids.append({'domain': target.domain, 'task_id': task.id})
        return Response({
            'tasks': task_ids,
            'count': len(task_ids),
            'status': 'batch_vt_check_queued',
        }, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Return aggregate dashboard stats for brand monitoring.
        Uses SQL aggregation for performance.
        """
        org_id = get_user_org_id(self.request)
        self._sync_targets(org_id)
        targets = BrandMonitorTarget.objects.filter(org_id=org_id)
        reports = VirusTotalReport.objects.filter(org_id=org_id)

        totals = reports.aggregate(
            total_malicious=Sum('malicious'),
            total_suspicious=Sum('suspicious'),
        )
        total_malicious = totals['total_malicious'] or 0
        total_suspicious = totals['total_suspicious'] or 0

        status_counts = dict(
            targets.values('status').annotate(count=Count('id')).values_list('status', 'count')
        )

        org_name = "Unknown"
        try:
            from authentication.models import Organization
            org = Organization.objects.filter(org_id=org_id).first()
            if org:
                org_name = org.name
        except Exception as e:
            logger = __import__('logging').getLogger(__name__)
            logger.warning("Failed to lookup org %s: %s", org_id, e)

        latest_ids = []
        for target in targets.only('id'):
            latest = VirusTotalReport.objects.filter(target=target) \
                .order_by('-checked_at').values_list('id', flat=True).first()
            if latest:
                latest_ids.append(latest)

        latest_reports = VirusTotalReport.objects.filter(id__in=latest_ids) \
            .select_related('target').order_by('-checked_at')[:10]

        serializer = BrandMonitorDashboardSerializer(data={
            'total_targets': targets.count(),
            'total_reports': reports.count(),
            'active_targets': targets.filter(is_active=True).count(),
            'total_malicious': total_malicious,
            'total_suspicious': total_suspicious,
            'org_name': org_name,
            'latest_reports': VirusTotalReportSerializer(latest_reports, many=True).data,
            'targets_by_status': status_counts,
        })
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.data)


class VirusTotalReportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only view of VirusTotal report results.
    """
    serializer_class = VirusTotalReportSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = "brand_monitoring"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        qs = VirusTotalReport.objects.filter(org_id=org_id).select_related('target')

        target_id = self.request.query_params.get('target')
        if target_id:
            qs = qs.filter(target_id=target_id)

        return qs


class SuspiciousDomainReportViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Suspicious Domain WHOIS and DNS Analysis.
    """
    serializer_class = SuspiciousDomainReportSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = "brand_monitoring"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return SuspiciousDomainReport.objects.filter(org_id=org_id)


    def create(self, request, *args, **kwargs):
        domain = request.data.get('domain', '').strip().lower()
        if not domain:
            return Response({"detail": "Domain is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        org_id = get_user_org_id(self.request)
        
        # Create pending report
        report = SuspiciousDomainReport.objects.create(
            domain=domain,
            status='pending',
            org_id=org_id
        )
        
        # Queue task
        task = analyze_suspicious_domain_task.delay(report.id)
        
        serializer = self.get_serializer(report)
        return Response({
            "report": serializer.data,
            "task_id": task.id
        }, status=status.HTTP_201_CREATED)


class PhishingDomainReportViewSet(viewsets.ModelViewSet):
    """
    ViewSet for look-alike Phishing Domain discoveries and URLScan/technology intelligence.
    """
    serializer_class = PhishingDomainReportSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = "brand_monitoring"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        qs = PhishingDomainReport.objects.filter(org_id=org_id)
        
        target_id = self.request.query_params.get('target')
        if target_id:
            qs = qs.filter(target_id=target_id)
            
        return qs

    def create(self, request, *args, **kwargs):
        import urllib.parse
        import threading
        import logging as _logging

        org_id = get_user_org_id(self.request)
        raw_target_id = request.data.get('target_id')
        raw_domain = request.data.get('domain', '').strip()

        target = None

        # Case 1: target_id is a numeric primary key — look up existing target
        if raw_target_id is not None:
            try:
                target_pk = int(raw_target_id)
                target = BrandMonitorTarget.objects.get(id=target_pk, org_id=org_id)
            except (ValueError, TypeError, BrandMonitorTarget.DoesNotExist):
                return Response(
                    {"detail": f"Target with id={raw_target_id} not found."},
                    status=status.HTTP_404_NOT_FOUND
                )

        # Case 2: domain string provided — extract apex domain & get_or_create target
        elif raw_domain:
            def _extract_domain(val):
                val = str(val).strip().lower()
                if not val.startswith(('http://', 'https://')):
                    if '/' in val:
                        val = 'http://' + val
                    else:
                        host = val.split(':')[0]
                        if host.startswith('www.'):
                            host = host[4:]
                        return host
                try:
                    parsed = urllib.parse.urlparse(val)
                    host = parsed.netloc or parsed.path
                    if ':' in host:
                        host = host.split(':')[0]
                    if host.startswith('www.'):
                        host = host[4:]
                    return host
                except Exception:
                    return val

            domain = _extract_domain(raw_domain)
            if not domain:
                return Response({"detail": "Could not extract a valid domain from the provided input."}, status=status.HTTP_400_BAD_REQUEST)

            target, _ = BrandMonitorTarget.objects.get_or_create(
                domain=domain,
                org_id=org_id,
                defaults={
                    'brand_name': domain.split('.')[0].capitalize(),
                    'is_active': True,
                    'status': 'active'
                }
            )
        else:
            return Response({"detail": "Either domain or target_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Run scan in a real background thread — bypasses CELERY_TASK_ALWAYS_EAGER=True
        # which would otherwise block the HTTP request for minutes of DNS lookups.
        def _run_in_background(target_id):
            try:
                # .run() calls the task function directly, bypassing the broker and the
                # Celery 'self' (bind=True) argument — works even with ALWAYS_EAGER=True.
                analyze_phishing_domain_task.run(target_id)
            except Exception as e:
                _logging.getLogger(__name__).error(
                    f"Background phishing scan failed for target {target_id}: {e}"
                )

        thread = threading.Thread(target=_run_in_background, args=(target.id,), daemon=True)
        thread.start()

        return Response({
            "status": "queued",
            "task_id": f"thread-{target.id}",
            "target_id": target.id,
            "domain": target.domain
        }, status=status.HTTP_202_ACCEPTED)


# ──────────────────────────────────────────────────────────────────────────────
# Impersonating Account Discovery ViewSets
# ──────────────────────────────────────────────────────────────────────────────

class ImpersonatingScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Impersonating Account scans.
    POST /api/brand-monitoring/impersonation-scans/  → trigger a new scan
    GET  /api/brand-monitoring/impersonation-scans/  → list all scans for org
    GET  /api/brand-monitoring/impersonation-scans/{id}/ → detail + results
    """
    serializer_class = ImpersonatingScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = "brand_monitoring"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return ImpersonatingScan.objects.filter(org_id=org_id)

    def create(self, request, *args, **kwargs):
        import threading
        import logging as _logging
        from .impersonation_tasks import run_impersonation_scan

        org_id = get_user_org_id(request)
        username = request.data.get("username", "").strip().lstrip("@")
        brand_domain = request.data.get("brand_domain", "").strip()
        org_name = request.data.get("org_name", "").strip()

        # Auto-populate org_name from Organization model if not provided
        if not org_name:
            try:
                org = Organization.objects.filter(org_id=org_id).first()
                if org and org.name:
                    org_name = org.name.strip()
            except Exception as e:
                _logging.getLogger(__name__).warning(f"Failed to auto-populate org_name: {e}")

        if not username:
            if org_name:
                username = "".join(e for e in org_name if e.isalnum()).lower()
            if not username:
                return Response({"detail": "username is required or no organization name found."}, status=status.HTTP_400_BAD_REQUEST)

        # Auto-detect brand_domain from org's first BrandMonitorTarget if not provided
        if not brand_domain:
            target = BrandMonitorTarget.objects.filter(org_id=org_id).first()
            brand_domain = target.domain if target else ""

        scan = ImpersonatingScan.objects.create(
            username=username,
            brand_domain=brand_domain,
            org_name=org_name,
            org_id=org_id,
            status="pending",
        )

        def _bg(scan_id):
            try:
                run_impersonation_scan(scan_id)
            except Exception as e:
                _logging.getLogger(__name__).error(f"Impersonation scan {scan_id} failed: {e}")
                try:
                    ImpersonatingScan.objects.filter(id=scan_id).update(status="failed")
                except Exception:
                    pass

        threading.Thread(target=_bg, args=(scan.id,), daemon=True).start()

        return Response({
            "status": "queued",
            "scan_id": scan.id,
            "username": scan.username,
            "brand_domain": scan.brand_domain,
            "org_name": scan.org_name,
        }, status=status.HTTP_202_ACCEPTED)


class ImpersonatingAccountResultViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Impersonating Account results.
    GET  /api/brand-monitoring/impersonation-results/?scan=<id>
    PATCH /api/brand-monitoring/impersonation-results/{id}/  → update action_status / action_team
    """
    serializer_class = ImpersonatingAccountResultSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = "brand_monitoring"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        qs = ImpersonatingAccountResult.objects.filter(org_id=org_id)
        scan_id = self.request.query_params.get("scan")
        platform = self.request.query_params.get("platform")
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        if platform:
            qs = qs.filter(platform=platform.lower())
        return qs

    def partial_update(self, request, *args, **kwargs):
        """Allow updating action_status and action_team only."""
        instance = self.get_object()
        allowed = {"action_status", "action_team"}
        data = {k: v for k, v in request.data.items() if k in allowed}
        serializer = self.get_serializer(instance, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
