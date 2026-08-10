import os, sys, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
django.setup()
from attacksurface.services import run_email_security

res = run_email_security("hackersinfotech.com")
print(json.dumps(res, indent=2))
