import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from attacksurface.services import run_nuclei
from attacksurface.models import VulnerabilityResult, AttackSurfaceScan

# Create a scan if it doesn't exist
scan = AttackSurfaceScan.objects.filter(target="brokencrystals.com").first()
if not scan:
    scan = AttackSurfaceScan.objects.create(target="brokencrystals.com", status="Running")

print("Running nuclei on brokencrystals.com...")
results = run_nuclei(["https://brokencrystals.com"], http_timeout=5)
print(f"Nuclei found {len(results)} vulnerabilities.")

for v in results:
    VulnerabilityResult.objects.get_or_create(
        scan=scan,
        domain="brokencrystals.com",
        template_id=v.get('template_id'),
        target=v.get('target', ''),
        defaults={
            'name': v.get('name', 'Unknown'),
            'severity': v.get('severity', 'info'),
            'type': v.get('type', ''),
            'source_tool': 'Nuclei',
            'raw_data': v
        }
    )
print("Finished saving to DB!")
scan.status = 'Completed'
scan.save()
