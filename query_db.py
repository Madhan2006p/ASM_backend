import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'integrated_backend.settings')
django.setup()
from attacksurface.models import VulnerabilityResult

# Get latest scan
from attacksurface.models import AttackSurfaceScan
scan = AttackSurfaceScan.objects.last()
print(f"Latest Scan ID: {scan.id}, Target: {scan.target}")
vulns = VulnerabilityResult.objects.filter(scan=scan)
print(f"Total Vulns for this scan: {vulns.count()}")
for v in vulns[:5]:
    print(v.source_tool, v.vulnerability_id, v.template_id, v.subdomain)
