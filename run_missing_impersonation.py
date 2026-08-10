import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

import threading
from brand_monitoring.models import BrandMonitorTarget, ImpersonatingScan
from brand_monitoring.impersonation_tasks import run_impersonation_scan
from authentication.models import Organization

targets = BrandMonitorTarget.objects.filter(is_active=True)
for target in targets:
    domain = target.domain
    org_id = target.org_id
    
    org_name_val = domain.split('.')[0].capitalize()
    try:
        org = Organization.objects.filter(org_id=org_id).first()
        if org and org.name:
            org_name_val = org.name.strip()
    except Exception:
        pass
        
    username_val = "".join(e for e in org_name_val if e.isalnum()).lower()
    if not username_val:
        username_val = domain.split('.')[0].lower()

    # Create scan if not exists for this username and domain
    i_scan, created = ImpersonatingScan.objects.get_or_create(
        username=username_val,
        brand_domain=domain,
        org_id=org_id,
        defaults={
            'org_name': org_name_val,
            'status': "pending"
        }
    )
    
    if i_scan.status != 'completed':
        print(f"Running impersonation scan for {domain} ({username_val})...")
        def _run_impersonation(s_id):
            try:
                run_impersonation_scan(s_id)
            except Exception as e:
                pass
        t = threading.Thread(target=_run_impersonation, args=(i_scan.id,))
        t.start()
        t.join() # Wait for it to finish for the script
        print(f"Finished {domain}")

print("Done all!")
