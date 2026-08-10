import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
from attacksurface.services import run_full_scan

scan = AttackSurfaceScan.objects.get(id=34)
print(f"Testing run_full_scan for scan {scan.id} target {scan.target}")
try:
    run_full_scan(scan)
except Exception as e:
    import traceback
    traceback.print_exc()
