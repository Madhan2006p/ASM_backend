import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import AttackSurfaceScan
scan = AttackSurfaceScan.objects.last()
print(f"Testing with scan ID: {scan.id}")

from attacksurface.services import run_full_scan
# We just want to make sure it loads correctly.
# We won't actually run it because it takes a long time.
print("Imports and definitions look good.")
