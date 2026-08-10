import os, sys, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
django.setup()
from django.test import Client
from attacksurface.models import EmailSecurityResult

latest = EmailSecurityResult.objects.order_by('-id').first()
c = Client()
res = c.get(f'/api/attacksurface/email-security/?scan={latest.scan.id}')
print(json.dumps(res.json(), indent=2))
