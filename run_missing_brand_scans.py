import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

import threading
from brand_monitoring.models import BrandMonitorTarget, SuspiciousDomainReport
from brand_monitoring.tasks import check_domain_virustotal, analyze_suspicious_domain_task, analyze_phishing_domain_task

targets = BrandMonitorTarget.objects.filter(is_active=True)
for target in targets:
    print(f"Triggering for {target.domain}...")
    try:
        check_domain_virustotal.delay(target_id=target.id)
    except Exception as e:
        print("VT error:", e)
        
    try:
        s_report, _ = SuspiciousDomainReport.objects.get_or_create(
            domain=target.domain,
            org_id=target.org_id,
            defaults={'status': 'pending'}
        )
        if s_report.status != 'completed':
            analyze_suspicious_domain_task.delay(s_report.id)
    except Exception as e:
        print("Suspicious error:", e)
        
    try:
        def _run_phishing(t_id):
            try:
                analyze_phishing_domain_task.run(t_id)
            except Exception as e:
                pass
        threading.Thread(target=_run_phishing, args=(target.id,), daemon=True).start()
    except Exception as e:
        print("Phishing error:", e)

print("Done triggering!")
