import os, sys, traceback
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
from attacksurface.views import start_attack_surface_scan

scan = start_attack_surface_scan("hackersinfotech.com", org_id="hackers-info-tech")
print(f"Created scan {scan.id}")

import time
for i in range(10):
    time.sleep(2)
    scan.refresh_from_db()
    print(f"[{i}] Status: {scan.status}, Progress: {scan.progress}, Error: {getattr(scan, 'error_message', 'No err msg')}")

