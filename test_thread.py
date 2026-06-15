import os, sys, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.views import start_attack_surface_scan
from attacksurface.models import AttackSurfaceScan

scan = start_attack_surface_scan("hackersinfotech.com")
print(f"Created scan {scan.id}")

for i in range(10):
    time.sleep(2)
    scan.refresh_from_db()
    print(f"[{i}] Status: {scan.status}, Progress: {scan.progress}")
