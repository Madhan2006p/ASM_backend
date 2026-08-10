import os, sys, traceback
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
from attacksurface.services import run_full_scan

scan = AttackSurfaceScan.objects.create(target="hackersinfotech.com", org_id="hackers-info-tech", status="pending")
print(f"Created scan {scan.id}")

try:
    run_full_scan(scan)
except Exception as e:
    print(f"FAILED WITH EXCEPTION: {e}")
    traceback.print_exc()

print(f"Final status: {scan.status}, progress: {scan.progress}")
