import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from brand_monitoring.impersonation_tasks import run_impersonation_scan
from brand_monitoring.models import ImpersonatingScan

scan = ImpersonatingScan.objects.create(
    username="testuser",
    brand_domain="test.com",
    org_name="test org",
    org_id=1,
    status="pending"
)
print("Running scan for ID:", scan.id)
run_impersonation_scan(scan.id)
print("Scan completed. Status:", scan.status)
