import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from brand_monitoring.models import BrandMonitorTarget, PhishingDomainReport
from brand_monitoring.tasks import analyze_phishing_domain_task
import urllib.parse

def test_flow(url_input):
    print(f"=== Testing URL input: {url_input} ===")
    
    # Exact extraction logic from views.py
    def _extract_domain(val):
        val = str(val).strip().lower()
        if not val.startswith(('http://', 'https://')):
            if '/' in val:
                val = 'http://' + val
            else:
                host = val.split(':')[0]
                if host.startswith('www.'):
                    host = host[4:]
                return host
        try:
            parsed = urllib.parse.urlparse(val)
            host = parsed.netloc or parsed.path
            if ':' in host:
                host = host.split(':')[0]
            if host.startswith('www.'):
                host = host[4:]
            return host
        except Exception:
            return val
            
    domain = _extract_domain(url_input)
    print(f"Extracted Domain: {domain}")
    
    # Get or create target dynamically (using org_id=1 for testing)
    target, created = BrandMonitorTarget.objects.get_or_create(
        domain=domain,
        org_id=1,
        defaults={
            'brand_name': domain.split('.')[0].capitalize(),
            'is_active': True,
            'status': 'active'
        }
    )
    print(f"BrandMonitorTarget ID: {target.id} | Created: {created} | Domain: {target.domain}")
    
    # Run analysis synchronously
    print("Running analyze_phishing_domain_task synchronously...")
    res = analyze_phishing_domain_task(target.id)
    print(f"Analysis result: {res}")
    
    # Retrieve generated reports
    reports = PhishingDomainReport.objects.filter(target=target)
    print(f"Total reports generated in DB: {reports.count()}")
    for idx, r in enumerate(reports[:5]):
        print(f"  [{idx + 1}] Domain: {r.domain:<20} | Type: {r.variation_type:<15} | Active: {r.is_active:<5} | URLScan: {r.urlscan_status}")

if __name__ == '__main__':
    # Test with a custom URL
    test_flow("https://github.com/django/django")
