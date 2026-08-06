import os
import shutil
import sqlite3
import threading
import subprocess
import tempfile
import time
import json
from pathlib import Path
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView

from authentication.permissions import IsAuthenticatedAndOrgMember, get_user_org_id
from .models import SpiderfootScan, SpiderfootResult
from .serializers import SpiderfootScanSerializer, SpiderfootResultSerializer

# Spiderfoot's internal scan database. Results are streamed from here while the
# scan is still running so the module shows live findings instead of waiting
# for the final JSON dump.
SPIDERFOOT_DB_PATH = os.getenv(
    'SPIDERFOOT_DB_PATH',
    str(Path.home() / '.spiderfoot' / 'spiderfoot.db'),
)
RESULT_POLL_SECONDS = float(os.getenv('SPIDERFOOT_RESULT_POLL', '10'))
SCAN_TIMEOUT_SECONDS = float(os.getenv('SPIDERFOOT_SCAN_TIMEOUT', '3600'))


def _resolve_spiderfoot():
    """
    Resolve the Spiderfoot CLI to execute.

    Returns a (python_bin, sf_path) tuple, or (None, None) when Spiderfoot
    cannot be located. Resolution order:
      1. SPIDERFOOT_PYTHON / SPIDERFOOT_SF_PATH environment variables
      2. ~/spiderfoot/ (venv + sf.py)  — typical local install
      3. Legacy path used by the original developer machine
      4. A `spiderfoot` executable on PATH
    """
    python_bin = os.getenv('SPIDERFOOT_PYTHON')
    sf_path = os.getenv('SPIDERFOOT_SF_PATH')

    candidates = [
        (python_bin, sf_path),
        (str(Path.home() / 'spiderfoot' / 'venv' / 'bin' / 'python'),
         str(Path.home() / 'spiderfoot' / 'sf.py')),
        ('/home/madhan/Desktop/spiderfoot/venv/bin/python',
         '/home/madhan/Desktop/spiderfoot/sf.py'),
    ]
    for py, sf in candidates:
        if py and sf and os.path.isfile(py) and os.path.isfile(sf):
            return py, sf

    which = shutil.which('spiderfoot')
    if which:
        return which, None
    return None, None


def _find_scan_instance_id(scan, db_path):
    """
    Find Spiderfoot's internal scan instance id for a Django scan.

    The instance is created inside Spiderfoot's own database when the scan
    starts, so it may not exist yet on the first call — callers should retry.
    """
    if not db_path or not os.path.isfile(db_path):
        return None
    start_ms = int(scan.created_at.timestamp() * 1000)
    try:
        con = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True, timeout=15)
        try:
            cur = con.cursor()
            # First instance started after this scan was created. ASC (rather
            # than DESC) keeps correlation correct even when two scans of the
            # same target overlap.
            cur.execute(
                "SELECT guid FROM tbl_scan_instance "
                "WHERE seed_target = ? AND started >= ? "
                "ORDER BY started ASC LIMIT 1",
                (scan.target, start_ms),
            )
            row = cur.fetchone()
            return row[0] if row else None
        finally:
            con.close()
    except Exception as exc:
        print("Spiderfoot scan instance lookup failed:", exc)
        return None


def _import_incremental_results(scan, instance_guid, seen_hashes, db_path):
    """
    Import Spiderfoot results accumulated so far for this scan instance.

    Rows already imported for this scan (tracked by their spiderfoot hash) are
    skipped, so repeated polls are idempotent. Returns the number of new rows.
    """
    if not instance_guid or not db_path or not os.path.isfile(db_path):
        return 0
    try:
        con = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True, timeout=15)
        try:
            cur = con.cursor()
            cur.execute(
                "SELECT hash, type, module, data FROM tbl_scan_results "
                "WHERE scan_instance_id = ?",
                (instance_guid,),
            )
            new_rows = []
            for h, data_type, module, data in cur.fetchall():
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                new_rows.append(SpiderfootResult(
                    scan=scan,
                    data_type=str(data_type or 'Unknown')[:255],
                    data_value=str(data or ''),
                    module=str(module or 'Spiderfoot')[:255],
                    source=str(instance_guid)[:255],
                ))
            if new_rows:
                SpiderfootResult.objects.bulk_create(new_rows)
            return len(new_rows)
        finally:
            con.close()
    except Exception as exc:
        print("Spiderfoot DB result import failed:", exc)
        return 0


def _import_json_results(scan, json_text):
    """Fallback importer used when Spiderfoot's internal DB is unavailable."""
    start_idx = json_text.find('[')
    end_idx = json_text.rfind(']')
    if start_idx == -1 or end_idx == -1:
        return 0
    try:
        items = json.loads(json_text[start_idx:end_idx + 1])
    except (ValueError, TypeError):
        return 0
    results_to_create = []
    for item in items:
        results_to_create.append(SpiderfootResult(
            scan=scan,
            data_type=str(item.get('type', 'Unknown'))[:255],
            data_value=item.get('data', ''),
            module=str(item.get('module', 'Spiderfoot'))[:255],
            source=str(item.get('source', ''))[:255],
        ))
    if results_to_create:
        SpiderfootResult.objects.bulk_create(results_to_create)
    return len(results_to_create)


def run_spiderfoot_scan_thread(scan_id):
    try:
        scan = SpiderfootScan.objects.get(id=scan_id)
    except SpiderfootScan.DoesNotExist:
        return

    scan.status = 'running'
    scan.save()

    python_bin, sf_path = _resolve_spiderfoot()
    if not python_bin:
        scan.status = 'failed'
        scan.completed_at = timezone.now()
        scan.save()
        print(
            "Spiderfoot scan failed: spiderfoot installation not found. "
            "Set SPIDERFOOT_PYTHON and SPIDERFOOT_SF_PATH env vars, or "
            "install Spiderfoot at ~/spiderfoot/."
        )
        return

    # `sf_path` is None when a single `spiderfoot` executable on PATH is used.
    cmd = [python_bin]
    if sf_path:
        cmd.append(sf_path)
    cmd += ["-s", scan.target, "-u", "all", "-q", "-o", "json"]

    db_path = SPIDERFOOT_DB_PATH
    seen_hashes = set()
    instance_guid = None
    total_imported = 0

    # Capture stdout/stderr to temp files instead of pipes so the child can
    # never block on a full pipe buffer; the stdout file also serves as a JSON
    # fallback source and stderr keeps failure diagnostics available.
    tmp_out = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
    tmp_err = tempfile.NamedTemporaryFile(delete=False, suffix='.err')
    try:
        proc = subprocess.Popen(
            cmd, stdout=tmp_out, stderr=tmp_err,
        )
    except Exception as e:
        tmp_out.close()
        tmp_err.close()
        for p in (tmp_out.name, tmp_err.name):
            try:
                os.unlink(p)
            except OSError:
                pass
        import traceback
        traceback.print_exc()
        print("Spiderfoot scan thread exception:", e)
        scan.status = 'failed'
        scan.completed_at = timezone.now()
        scan.save()
        return

    try:
        # Stream results from Spiderfoot's internal DB while the scan runs,
        # so findings appear live instead of only after completion.
        deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
        timed_out = False
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
                print(
                    f"Spiderfoot scan {scan.id} timed out after "
                    f"{int(SCAN_TIMEOUT_SECONDS)}s; terminating process."
                )
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
                break
            if not instance_guid:
                instance_guid = _find_scan_instance_id(scan, db_path)
            if instance_guid:
                imported = _import_incremental_results(
                    scan, instance_guid, seen_hashes, db_path
                )
                if imported:
                    total_imported += imported
                    print(
                        f"Spiderfoot scan {scan.id}: "
                        f"imported {imported} new results (total {total_imported})"
                    )
            time.sleep(RESULT_POLL_SECONDS)

        # Final sweep after the process exits.
        if not instance_guid:
            instance_guid = _find_scan_instance_id(scan, db_path)
        total_imported += _import_incremental_results(
            scan, instance_guid, seen_hashes, db_path
        )

        if timed_out:
            scan.status = 'failed'
        elif proc.returncode == 0:
            # Fallback: if the DB import found nothing (e.g. non-standard DB
            # location), parse the JSON dump written to the temp file.
            if total_imported == 0:
                tmp_out.flush()
                try:
                    with open(tmp_out.name, 'r', errors='replace') as f:
                        json_text = f.read()
                    total_imported += _import_json_results(scan, json_text)
                except OSError as exc:
                    print("Spiderfoot JSON fallback read failed:", exc)
            scan.status = 'completed'
        else:
            print("Spiderfoot scan process failed with code:", proc.returncode)
            try:
                with open(tmp_err.name, 'r', errors='replace') as f:
                    stderr_tail = '\n'.join(f.readlines()[-20:])
                if stderr_tail.strip():
                    print("Spiderfoot stderr tail:", stderr_tail)
            except OSError:
                pass
            scan.status = 'failed'
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("Spiderfoot scan thread exception:", e)
        scan.status = 'failed'
        print(f"Spiderfoot scan failed for {scan.target}: {e}")
    finally:
        tmp_out.close()
        tmp_err.close()
        for p in (tmp_out.name, tmp_err.name):
            try:
                os.unlink(p)
            except OSError:
                pass
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
        # Any scan still marked 'running' for the same target is stale (e.g.
        # its process was orphaned by a backend restart). Mark it failed so
        # duplicate live scans for one target can never pile up.
        SpiderfootScan.objects.filter(
            target=scan.target, status='running',
        ).exclude(id=scan.id).update(
            status='failed', completed_at=timezone.now(),
        )
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
