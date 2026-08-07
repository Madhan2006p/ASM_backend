import os, sys, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
django.setup()

from attacksurface.services import run_email_security
domain = "globalcyberalliance.org"
print(f"Running email security scan on {domain} using DSS...")
result = run_email_security(domain)
print(json.dumps(result, indent=2))
