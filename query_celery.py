import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
scan = AttackSurfaceScan.objects.get(id=40)
print(f"Status: {scan.status}, Progress: {scan.progress}")
