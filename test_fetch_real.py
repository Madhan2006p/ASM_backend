import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.faraday_import import fetch_faraday_findings
res = fetch_faraday_findings()
for f in res.get('findings', []):
    print(f"{f['severity']} | {f['title']} | {f['endpoint']}")
