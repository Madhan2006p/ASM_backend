import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
scan = AttackSurfaceScan.objects.last()
print(f"ID: {scan.id}, Target: {scan.target}, Status: {scan.status}, Progress: {scan.progress}, Created: {scan.created_at}")
