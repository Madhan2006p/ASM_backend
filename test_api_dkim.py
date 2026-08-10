import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
django.setup()
from attacksurface.models import EmailSecurityResult
from django.test import RequestFactory
from attacksurface.views import EmailSecurityView
import json

latest = EmailSecurityResult.objects.order_by('-id').first()
factory = RequestFactory()
request = factory.get(f'/api/attacksurface/email-security/?scan={latest.scan.id}')
response = EmailSecurityView.as_view()(request)
print(json.dumps(response.data, indent=2))
