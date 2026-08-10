import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import VulnerabilityResult, AttackSurfaceScan
scans = AttackSurfaceScan.objects.filter(target="kct.ac.in")
for scan in scans:
    vulns = VulnerabilityResult.objects.filter(scan_id=scan.id)
    print(f"Scan {scan.id} -> {vulns.count()} vulns")
