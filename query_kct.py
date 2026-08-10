import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import VulnerabilityResult, AttackSurfaceScan
scan = AttackSurfaceScan.objects.filter(target="kct.ac.in").last()
vulns = VulnerabilityResult.objects.filter(scan_id=scan.id)
for v in vulns:
    print(f"{v.severity} | {v.vulnerability_id} | {v.subdomain}")
