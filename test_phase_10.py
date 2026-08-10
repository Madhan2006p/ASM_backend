import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import VulnerabilityResult, AttackSurfaceScan

scan = AttackSurfaceScan.objects.get(id=40)
vulns = VulnerabilityResult.objects.filter(scan=scan)
print(f"Scan {scan.id} vulns count: {vulns.count()}")
for v in vulns[:5]:
    print(v.finding, v.severity, v.vulnerability_id)
