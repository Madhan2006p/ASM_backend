import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
scan = AttackSurfaceScan.objects.last()
print(f"Status: {scan.status}")
print(f"Progress: {scan.progress}")
print(f"Phase: {scan.current_phase}")
print(f"Error: {scan.error_message}")
