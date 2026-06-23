import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'integrated_backend.settings')
django.setup()
from django.test import RequestFactory
from mobile_vapt.views import AllFindingsView
factory = RequestFactory()
request = factory.get('/api/mobile-vapt/findings/', {'category': 'Security Analysis', 'page_size': '2'})
response = AllFindingsView.as_view()(request)
print(response.data)
