import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.faraday_import import _get_authenticated_session
session = _get_authenticated_session()
url = "http://localhost:5985/_api/v3/ws/nuclei-asm/vulns"
resp = session.get(url)
vulns = resp.json().get('vulnerabilities', [])
print(f"Total raw vulns: {len(vulns)}")
for v in vulns:
    val = v.get('value', {})
    print(val.get('name'))
