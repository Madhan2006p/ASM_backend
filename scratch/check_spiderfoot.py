import os
import django
import sys

sys.path.append("/home/madhan/Desktop/ASM-New/integrated_backend")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from surface_monitoring.models import SpiderfootScan
from attacksurface.models import AttackSurfaceScan

print("Querying latest AttackSurfaceScan records:")
scans = AttackSurfaceScan.objects.all().order_by("-created_at")
print("Total AttackSurfaceScan count:", scans.count())
for s in scans[:10]:
    print(f"ID: {s.id}, Target: {s.target}, Status: {s.status}, Org ID: {s.org_id}, Created: {s.created_at}")

print("\nQuerying SpiderfootScan records:")
sf_scans = SpiderfootScan.objects.all().order_by("-created_at")
print("Total SpiderfootScan count:", sf_scans.count())
for s in sf_scans[:10]:
    print(f"ID: {s.id}, Target: {s.target}, Status: {s.status}, Org ID: {s.org_id}, Created: {s.created_at}")
