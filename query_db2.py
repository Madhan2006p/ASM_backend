import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'integrated_backend.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()
from attacksurface.models import VulnerabilityResult, AttackSurfaceScan

scan = AttackSurfaceScan.objects.last()
vulns = VulnerabilityResult.objects.filter(scan=scan, source_tool='Nuclei')
print(f"Nuclei vulns in DB for scan {scan.id}: {vulns.count()}")
for v in vulns[:5]:
    print(v.template_id, v.vulnerability_id, v.subdomain)
