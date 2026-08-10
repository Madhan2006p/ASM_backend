import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.faraday_import import _get_authenticated_session
from django.conf import settings
import json

session = _get_authenticated_session()
base = "http://localhost:5985"
url = f"{base}/_api/v3/ws/nuclei-asm/vulns"
resp = session.get(url)
vulns = resp.json().get('vulnerabilities', [])
if vulns:
    print(json.dumps(vulns[0], indent=2))
