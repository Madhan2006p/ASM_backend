import os
import threading
import subprocess
import json
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView

from authentication.permissions import IsAuthenticatedAndOrgMember, get_user_org_id
from .models import SpiderfootScan, SpiderfootResult
from .serializers import SpiderfootScanSerializer, SpiderfootResultSerializer

def run_spiderfoot_scan_thread(scan_id):
    try:
        scan = SpiderfootScan.objects.get(id=scan_id)
    except SpiderfootScan.DoesNotExist:
        return

    scan.status = 'running'
    scan.save()

    cmd = [
        "/home/madhan/Desktop/spiderfoot/venv/bin/python",
        "/home/madhan/Desktop/spiderfoot/sf.py",
        "-s", scan.target,
        "-u", "all",
        "-q",
        "-o", "json"
    ]
    try:
        # Give it up to 3600 seconds to finish passive scan
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if result.returncode == 0:
            stdout_data = result.stdout.strip()
            if stdout_data:
                start_idx = stdout_data.find('[')
                end_idx = stdout_data.rfind(']')
                if start_idx != -1 and end_idx != -1:
                    json_str = stdout_data[start_idx:end_idx+1]
                    items = json.loads(json_str)
                    
                    results_to_create = []
                    for item in items:
                        results_to_create.append(SpiderfootResult(
                            scan=scan,
                            data_type=str(item.get('type', 'Unknown'))[:255],
                            data_value=item.get('data', ''),
                            module=str(item.get('module', 'Spiderfoot'))[:255],
                            source=str(item.get('source', ''))[:255]
                        ))
                    if results_to_create:
                        SpiderfootResult.objects.bulk_create(results_to_create)
            scan.status = 'completed'
        else:
            print("Spiderfoot scan process failed with code:", result.returncode)
            print("Spiderfoot stderr:", result.stderr)
            scan.status = 'failed'
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("Spiderfoot scan thread exception:", e)
        scan.status = 'failed'
    finally:
        scan.completed_at = timezone.now()
        scan.save()


class SpiderfootScanViewSet(viewsets.ModelViewSet):
    serializer_class = SpiderfootScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return SpiderfootScan.objects.filter(org_id=org_id)

    def perform_create(self, serializer):
        org_id = get_user_org_id(self.request)
        scan = serializer.save(org_id=org_id, status='pending')
        # Start scanning thread
        thread = threading.Thread(target=run_spiderfoot_scan_thread, args=(scan.id,), daemon=True)
        thread.start()

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        scan = self.get_object()
        results = scan.results.all()
        
        # Filter by data_type if provided
        data_type = request.query_params.get('type')
        if data_type:
            results = results.filter(data_type=data_type)
            
        serializer = SpiderfootResultSerializer(results, many=True)
        return Response(serializer.data)


class SpiderfootResultViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SpiderfootResultSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return SpiderfootResult.objects.filter(scan__org_id=org_id)


class SpiderfootStatsView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        org_id = get_user_org_id(request)
        scans = SpiderfootScan.objects.filter(org_id=org_id)
        results = SpiderfootResult.objects.filter(scan__org_id=org_id)

        # Count data types
        from django.db.models import Count
        type_counts = results.values('data_type').annotate(count=Count('id')).order_by('-count')
        type_counts_dict = {item['data_type']: item['count'] for item in type_counts}

        # Count modules
        module_counts = results.values('module').annotate(count=Count('id')).order_by('-count')
        module_counts_dict = {item['module']: item['count'] for item in module_counts}

        latest_findings = []
        for r in results.order_by('-created_at')[:15]:
            latest_findings.append({
                'id': r.id,
                'target': r.scan.target,
                'data_type': r.data_type,
                'data_value': r.data_value,
                'module': r.module,
                'created_at': r.created_at.strftime("%Y-%m-%d %H:%M:%S")
            })

        return Response({
            'total_scans': scans.count(),
            'completed_scans': scans.filter(status='completed').count(),
            'running_scans': scans.filter(status='running').count(),
            'total_results': results.count(),
            'type_counts': type_counts_dict,
            'module_counts': module_counts_dict,
            'latest_findings': latest_findings
        })
