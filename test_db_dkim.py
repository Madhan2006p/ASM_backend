import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
django.setup()
from attacksurface.models import EmailSecurityResult
import json

latest = EmailSecurityResult.objects.order_by('-id').first()
if latest:
    print(latest.domain)
    print(latest.dkim_default)
else:
    print("No records")
