import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
scans = AttackSurfaceScan.objects.filter().order_by('-created_at')[:5]
for scan in scans:
    print(f"ID: {scan.id}, Target: {scan.target}, Status: {scan.status}")
    try:
        print(f"Error: {scan.error_message}")
    except:
        pass
    print("-" * 20)
