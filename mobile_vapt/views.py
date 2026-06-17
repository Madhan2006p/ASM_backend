import os
import logging
from django.conf import settings
from django.db.models import Count, Q
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from .models import MobileScan, MobileFinding, MobilePermission, SecurityScore
from .serializers import (
    MobileScanSerializer, MobileFindingSerializer,
    MobilePermissionSerializer, SecurityScoreSerializer,
    FileUploadSerializer, DashboardSerializer
)
from .mobsf_integration import MobSFClient

logger = logging.getLogger(__name__)
mobsf = MobSFClient()


class FileUploadView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name

        if not any(file_name.endswith(ext) for ext in ['.apk', '.aab', '.ipa']):
            return Response(
                {'error': 'Unsupported file type. Upload APK, AAB, or IPA.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, file_name)

        with open(file_path, 'wb+') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)

        import uuid
        scan = MobileScan.objects.create(
            file_name=file_name,
            file_path=file_path,
            status='uploaded',
            scan_hash=f"temp_{uuid.uuid4()}"
        )

        if file_name.endswith('.ipa'):
            scan.source = 'ios'
        else:
            scan.source = 'android'
        scan.save()

        # Start background scan thread to avoid blocking and timing out
        import threading

        def run_scan_thread():
            from django.db import connection
            try:
                # Ensure MobSF is running before we try to upload to it
                from mobile_vapt.docker_manager import ensure_mobsf_running
                ensure_mobsf_running()

                mobsf_result = mobsf.upload_file(file_path)
                if mobsf_result and 'hash' in mobsf_result:
                    # Delete any pre-existing scan with the same hash to prevent UNIQUE constraint violation
                    MobileScan.objects.filter(scan_hash=mobsf_result['hash']).exclude(pk=scan.id).delete()

                    scan.scan_hash = mobsf_result['hash']
                    scan.status = 'uploaded_to_mobsf'
                    scan.save()

                    scan_result = mobsf.start_scan(scan.scan_hash, scan_type=scan.source)
                    if scan_result:
                        scan.status = 'scanning'
                        scan.save()

                        # MobSF start_scan returns full analysis data synchronously.
                        # Use it directly as the report; fall back to get_report_json if needed.
                        report = scan_result if scan_result.get('app_name') else mobsf.get_report_json(scan.scan_hash)
                        if report and report.get('app_name'):
                            scan.status = 'completed'
                            scan.app_name = report.get('app_name', '')
                            scan.package_name = report.get('package_name', '')
                            scan.version_name = report.get('version_name', '')
                            avg_score = report.get('average_cvss', 0)
                            scan.score = str(100 - int(avg_score * 10) if avg_score else 50)
                            scan.save()
                            self._store_findings(scan, report)
                            self._store_permissions(scan, report)
                            self._store_scores(scan, report)
                        else:
                            scan.status = 'report_failed'
                            scan.save()
                    else:
                        scan.status = 'scan_failed'
                        scan.save()
                else:
                    scan.status = 'upload_failed'
                    scan.save()
            except Exception as e:
                logger.error(f"Error in background scan thread: {e}", exc_info=True)
                try:
                    scan.status = 'scan_failed'
                    scan.save()
                except Exception:
                    pass
            finally:
                # Stop the MobSF Docker container now that scanning is done
                try:
                    from mobile_vapt.docker_manager import stop_mobsf
                    stop_mobsf()
                except Exception as stop_err:
                    logger.warning(f"Could not stop MobSF container: {stop_err}")
                connection.close()

        threading.Thread(target=run_scan_thread).start()

        serializer = MobileScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def _store_findings(self, scan, report):
        """
        Parse MobSF v4.5 report and store all real vulnerability findings.
        Covers: appsec, code_analysis, manifest_findings, certificate_findings,
                network_findings, binary_analysis, file_analysis.
        """

        # ── 1. APPSEC (main security summary) ──────────────────────────────
        # Structure: report['appsec'] = {'high': [...], 'warning': [...], 'info': [...], 'secure': [...], 'hotspot': [...]}
        # MobSF severity → normalized label (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        SEV = {
            'critical': 'CRITICAL', 'high': 'HIGH', 'warning': 'MEDIUM',
            'medium': 'MEDIUM', 'low': 'LOW', 'info': 'INFO',
            'secure': 'INFO', 'hotspot': 'MEDIUM', 'error': 'CRITICAL',
        }
        appsec_severity_map = {
            'high': 'HIGH',
            'warning': 'MEDIUM',
            'info': 'INFO',
            'secure': 'INFO',
            'hotspot': 'MEDIUM',
        }
        appsec = report.get('appsec', {})
        for sev_key, sev_label in appsec_severity_map.items():
            for item in appsec.get(sev_key, []):
                if not isinstance(item, dict):
                    continue
                MobileFinding.objects.create(
                    scan=scan,
                    vulnerability=item.get('title', 'Unknown')[:500],
                    severity=sev_label,
                    description=item.get('description', ''),
                    category='Security Analysis',
                    recommendation='',
                )

        # ── 2. CODE ANALYSIS ───────────────────────────────────────────────
        # Structure: report['code_analysis']['findings'] = {rule_id: {files: {}, metadata: {}}, ...}
        code_findings = report.get('code_analysis', {}).get('findings', {})
        if isinstance(code_findings, dict):
            for rule_id, finding_data in code_findings.items():
                if not isinstance(finding_data, dict):
                    continue
                metadata = finding_data.get('metadata', {})
                files_dict = finding_data.get('files', {})
                file_list = ', '.join(list(files_dict.keys())[:5]) if files_dict else ''
                severity_raw = str(metadata.get('severity', 'info')).lower()
                MobileFinding.objects.create(
                    scan=scan,
                    vulnerability=(metadata.get('description', rule_id))[:500],
                    severity=SEV.get(severity_raw, 'MEDIUM'),
                    description=metadata.get('description', ''),
                    category='Code Analysis',
                    file_path=file_list[:500],
                    recommendation=metadata.get('ref', ''),
                )

        # ── 3. MANIFEST ANALYSIS ───────────────────────────────────────────
        # Structure: report['manifest_analysis']['manifest_findings'] = [{rule, title, severity, description}, ...]
        manifest_findings = report.get('manifest_analysis', {}).get('manifest_findings', [])
        for item in manifest_findings:
            if not isinstance(item, dict):
                continue
            severity_raw = str(item.get('severity', 'info')).lower()
            MobileFinding.objects.create(
                scan=scan,
                vulnerability=item.get('title', 'Manifest Issue')[:500],
                severity=SEV.get(severity_raw, 'MEDIUM'),
                description=item.get('description', ''),
                category='Manifest Analysis',
                recommendation=item.get('rule', ''),
            )

        # ── 4. CERTIFICATE ANALYSIS ────────────────────────────────────────
        # Structure: report['certificate_analysis']['certificate_findings'] = [[severity, description, title], ...]
        cert_findings = report.get('certificate_analysis', {}).get('certificate_findings', [])
        for item in cert_findings:
            if isinstance(item, list) and len(item) >= 2:
                severity_raw = str(item[0]).lower()
                title = item[2] if len(item) > 2 else item[1]
                MobileFinding.objects.create(
                    scan=scan,
                    vulnerability=str(title)[:500],
                    severity=SEV.get(severity_raw, 'INFO'),
                    description=str(item[1]),
                    category='Certificate Analysis',
                )
            elif isinstance(item, dict):
                severity_raw = str(item.get('severity', 'info')).lower()
                MobileFinding.objects.create(
                    scan=scan,
                    vulnerability=item.get('title', 'Certificate Issue')[:500],
                    severity=SEV.get(severity_raw, 'INFO'),
                    description=item.get('description', ''),
                    category='Certificate Analysis',
                )

        # ── 5. NETWORK SECURITY ────────────────────────────────────────────
        # Structure: report['network_security']['network_findings'] = [{scope, description, severity}, ...]
        network_findings = report.get('network_security', {}).get('network_findings', [])
        for item in network_findings:
            if not isinstance(item, dict):
                continue
            severity_raw = str(item.get('severity', 'info')).lower()
            scope = item.get('scope', [])
            scope_str = ', '.join(scope) if isinstance(scope, list) else str(scope)
            MobileFinding.objects.create(
                scan=scan,
                vulnerability=f"Network: {item.get('description', 'Network Security Issue')[:480]}",
                severity=SEV.get(severity_raw, 'MEDIUM'),
                description=f"Scope: {scope_str}\n{item.get('description', '')}",
                category='Network Security',
            )

        # ── 6. BINARY ANALYSIS ─────────────────────────────────────────────
        # Structure: report['binary_analysis'] = [{name, nx: {severity, description}, pie: {...}, ...}, ...]
        binary_fields = ['nx', 'pie', 'stack_canary', 'relocation_readonly', 'rpath', 'runpath', 'fortify', 'symbol']
        for binary in report.get('binary_analysis', []):
            if not isinstance(binary, dict):
                continue
            binary_name = binary.get('name', 'Unknown binary')
            for field in binary_fields:
                field_data = binary.get(field, {})
                if not isinstance(field_data, dict):
                    continue
                severity_raw = str(field_data.get('severity', 'info')).lower()
                if severity_raw in ('info', 'secure'):
                    continue  # skip informational binary flags
                MobileFinding.objects.create(
                    scan=scan,
                    vulnerability=f"Binary: {binary_name} - {field.replace('_', ' ').upper()} missing"[:500],
                    severity=SEV.get(severity_raw, 'MEDIUM'),
                    description=field_data.get('description', ''),
                    category='Binary Analysis',
                    file_path=binary_name[:500],
                )

        # ── 7. FILE ANALYSIS ───────────────────────────────────────────────
        # Structure: report['file_analysis'] = [{finding, files: [...]}, ...]
        for item in report.get('file_analysis', []):
            if not isinstance(item, dict):
                continue
            files = item.get('files', [])
            file_str = ', '.join(files[:5]) if isinstance(files, list) else str(files)
            MobileFinding.objects.create(
                scan=scan,
                vulnerability=item.get('finding', 'Sensitive File Found')[:500],
                severity='CRITICAL',
                description=f"Found in files: {file_str}",
                category='File Analysis',
                file_path=file_str[:500],
            )

    def _store_permissions(self, scan, report):
        """
        Parse MobSF v4.5 permissions.
        Structure: report['permissions'] = {permission_name: {status, info, description}, ...}
        """
        permissions = report.get('permissions', {})
        if isinstance(permissions, dict):
            for perm_name, perm_data in permissions.items():
                if isinstance(perm_data, dict):
                    MobilePermission.objects.create(
                        scan=scan,
                        permission_name=perm_name[:500],
                        status=perm_data.get('status', ''),
                        description=perm_data.get('description', ''),
                        severity=perm_data.get('status', '').upper() if perm_data.get('status') else '',
                    )
        elif isinstance(permissions, list):
            for perm in permissions:
                if isinstance(perm, dict):
                    MobilePermission.objects.create(
                        scan=scan,
                        permission_name=perm.get('permission', '') or perm.get('name', ''),
                        status=perm.get('status', ''),
                        severity=perm.get('severity', ''),
                    )
                elif isinstance(perm, str):
                    MobilePermission.objects.create(scan=scan, permission_name=perm)

    def _store_scores(self, scan, report):
        avg_score = report.get('average_cvss', 0)
        SecurityScore.objects.create(
            scan=scan,
            category='Overall Security Score',
            score=100 - int(avg_score * 10) if avg_score else 50,
            max_score=100,
        )

        tracking_count = len(report.get('trackers', [])) if isinstance(report.get('trackers'), list) else 0
        SecurityScore.objects.create(
            scan=scan,
            category='Trackers Detected',
            score=max(0, 100 - tracking_count * 10),
            max_score=100,
        )


class ScanStatusView(APIView):
    def get(self, request, pk):
        try:
            scan = MobileScan.objects.get(pk=pk)
            serializer = MobileScanSerializer(scan)
            return Response(serializer.data)
        except MobileScan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)


class ScanFindingsView(APIView):
    def get(self, request, pk):
        try:
            scan = MobileScan.objects.get(pk=pk)
            findings = scan.findings.all()
            severity_filter = request.query_params.get('severity')
            if severity_filter:
                findings = findings.filter(severity__iexact=severity_filter)

            search = request.query_params.get('search')
            if search:
                findings = findings.filter(
                    Q(vulnerability__icontains=search) |
                    Q(description__icontains=search) |
                    Q(category__icontains=search)
                )

            permissions = MobilePermissionSerializer(scan.permissions.all(), many=True).data
            scores = SecurityScoreSerializer(scan.scores.all(), many=True).data

            return Response({
                'scan': MobileScanSerializer(scan).data,
                'findings': MobileFindingSerializer(findings, many=True).data,
                'permissions': permissions,
                'scores': scores,
                'total_findings': findings.count(),
            })
        except MobileScan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)


class AllFindingsView(APIView):
    def get(self, request):
        findings = MobileFinding.objects.all()

        severity = request.query_params.get('severity')
        if severity:
            findings = findings.filter(severity__iexact=severity)

        category = request.query_params.get('category')
        if category:
            findings = findings.filter(category__iexact=category)

        search = request.query_params.get('search')
        if search:
            findings = findings.filter(
                Q(vulnerability__icontains=search) |
                Q(description__icontains=search)
            )

        scan_id = request.query_params.get('scan_id')
        if scan_id:
            findings = findings.filter(scan_id=scan_id)

        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        total = findings.count()

        serializer = MobileFindingSerializer(findings[start:end], many=True)
        return Response({
            'count': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
            'results': serializer.data,
        })


class DashboardView(APIView):
    def get(self, request):
        total_scans = MobileScan.objects.count()
        completed_scans = MobileScan.objects.filter(status='completed').count()

        findings_count = MobileFinding.objects.count()
        severity_counts = MobileFinding.objects.values('severity').annotate(
            count=Count('id')
        ).order_by('severity')

        severity_dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'WARNING': 0}
        for item in severity_counts:
            sev = item['severity'].upper() if item['severity'] else 'INFO'
            if sev in severity_dist:
                severity_dist[sev] = item['count']
            else:
                severity_dist[sev] = item['count']

        category_counts = MobileFinding.objects.values('category').annotate(
            count=Count('id')
        ).filter(category__isnull=False).exclude(category='').order_by('-count')[:10]

        category_dist = {}
        for item in category_counts:
            cat = item['category'] if item['category'] else 'Uncategorized'
            category_dist[cat] = item['count']

        top_vulns = MobileFinding.objects.values('vulnerability', 'severity').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        recent_scans = MobileScan.objects.filter(status='completed')[:5]
        recent_data = MobileScanSerializer(recent_scans, many=True).data

        return Response({
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'total_findings': findings_count,
            'critical': severity_dist.get('CRITICAL', 0),
            'high': severity_dist.get('HIGH', 0),
            'medium': severity_dist.get('MEDIUM', 0),
            'low': severity_dist.get('LOW', 0),
            'info': severity_dist.get('INFO', 0),
            'severity_distribution': severity_dist,
            'category_distribution': category_dist,
            'top_vulnerabilities': list(top_vulns),
            'recent_scans': recent_data,
        })


class ScanHistoryView(APIView):
    def get(self, request):
        scans = MobileScan.objects.all()
        status_filter = request.query_params.get('status')
        if status_filter:
            scans = scans.filter(status=status_filter)

        search = request.query_params.get('search')
        if search:
            scans = scans.filter(
                Q(file_name__icontains=search) |
                Q(app_name__icontains=search) |
                Q(package_name__icontains=search)
            )

        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start = (page - 1) * page_size
        end = start + page_size
        total = scans.count()

        serializer = MobileScanSerializer(scans[start:end], many=True)
        return Response({
            'count': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
            'results': serializer.data,
        })


class ScanDetailView(APIView):
    def get(self, request, pk):
        try:
            scan = MobileScan.objects.get(pk=pk)
            findings = scan.findings.all()

            severity_counts = findings.values('severity').annotate(count=Count('id'))
            severity_dist = {item['severity']: item['count'] for item in severity_counts}

            return Response({
                'scan': MobileScanSerializer(scan).data,
                'findings': MobileFindingSerializer(findings, many=True).data,
                'permissions': MobilePermissionSerializer(scan.permissions.all(), many=True).data,
                'scores': SecurityScoreSerializer(scan.scores.all(), many=True).data,
                'severity_summary': severity_dist,
                'total_findings': findings.count(),
            })
        except MobileScan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)


class DeleteScanView(APIView):
    def delete(self, request, pk):
        try:
            scan = MobileScan.objects.get(pk=pk)
            file_path = scan.file_path
            scan.delete()

            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass

            return Response({'message': 'Scan deleted successfully'}, status=status.HTTP_200_OK)
        except MobileScan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)


class ClearAllScansView(APIView):
    def post(self, request):
        try:
            # Delete all scans; cascading will delete findings, permissions, scores
            MobileScan.objects.all().delete()
            return Response({'message': 'All history cleared successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
