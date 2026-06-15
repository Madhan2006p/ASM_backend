import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.services import run_nuclei
print("Running nuclei on hackersinfotech.com")
results = run_nuclei(["https://hackersinfotech.com"], http_timeout=5)
print(f"Results: {results}")
