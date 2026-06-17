import os
import sys
import django

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from brand_monitoring.tasks import analyze_phishing_domain_task
from brand_monitoring.models import BrandMonitorTarget, PhishingDomainReport

def test_phishing_logic():
    print("=== Testing Phishing Domain Scan Task ===")
    domain = "kct.ac.in"
    org_id = "1"
    
    # 1. Fetch or create monitored target
    target, created = BrandMonitorTarget.objects.get_or_create(
        domain=domain,
        org_id=org_id,
        defaults={'brand_name': 'KCT', 'is_active': True, 'status': 'active'}
    )
    
    # 2. Run the phishing scanner Celery task synchronously
    print(f"\n2. Running analyze_phishing_domain_task for '{domain}'...")
    result = analyze_phishing_domain_task(target_id=target.id)
    print("Task result:")
    for k, v in result.items():
        print(f"  {k}: {v}")
        
    # 3. Retrieve reports from DB
    reports = PhishingDomainReport.objects.filter(target=target)
    print(f"\n3. Discovered {reports.count()} lookalike domains in database:")
    
    # Print first few reports
    for idx, report in enumerate(reports[:5]):
        print(f"\n[{idx+1}] Domain: {report.domain}")
        print(f"  Variation: {report.variation_type}")
        print(f"  Active: {report.is_active}")
        print(f"  URLScan Status: {report.urlscan_status} (Score: {report.urlscan_score})")
        print(f"  Page Title: {report.page_title}")
        print(f"  Technologies: {report.technologies}")
        print(f"  Screenshot: {report.screenshot_url}")
        
    print("\n=== Phishing Logic Validation Complete ===")

if __name__ == "__main__":
    try:
        test_phishing_logic()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[FAILED] Phishing logic check failed: {e}")
