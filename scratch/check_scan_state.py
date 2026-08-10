import os, sys, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
django.setup()

from attacksurface.models import AttackSurfaceScan

print('Total AttackSurfaceScans:', AttackSurfaceScan.objects.count())
for s in AttackSurfaceScan.objects.order_by('-created_at')[:10]:
    fields = {}
    for f in s._meta.get_fields():
        if f.name in ('id', 'status', 'target', 'org_id', 'phase', 'progress', 'vuln_scan_phase', 'vulnerabilities_done', 'nuclei_phase', 'nuclei_found', 'created_at', 'started_at', 'completed_at', 'error_message', 'error', 'log'):
            try:
                fields[f.name] = getattr(s, f.name)
            except Exception as e:
                fields[f.name] = f'<err {e}>'
    print(fields)
