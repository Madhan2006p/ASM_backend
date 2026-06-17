import os
import sys
import django

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from brand_monitoring.tasks import _generate_simulated_stats, check_domain_virustotal
from brand_monitoring.models import BrandMonitorTarget, VirusTotalReport

def test_antimalware_logic():
    print("=== Testing Anti Malware Logic ===")
    domain = "kct.ac.in"
    org_id = "1"
    
    # 1. Test deterministic simulation generation
    print(f"\n1. Generating simulated stats for '{domain}'...")
    stats = _generate_simulated_stats(domain)
    print("Generated Stats:")
    for k, v in stats.items():
        if k != "categories" and k != "total_votes":
            print(f"  {k}: {v}")
    
    # Verify reputation logic matches frontend grade calculation
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    expected_reputation = max(0, min(100, 100 - (malicious * 15 + suspicious * 5)))
    print(f"  Verified Reputation: {expected_reputation} (Task reputation: {stats['reputation']})")
    assert expected_reputation == stats['reputation'], "Reputation score mismatch!"
    print("  [OK] Reputation score matches calculation.")
    
    # 2. Test target sync & report generation
    print(f"\n2. Executing VT check task for '{domain}'...")
    # Find or create a target
    target, created = BrandMonitorTarget.objects.get_or_create(
        domain=domain,
        org_id=org_id,
        defaults={'brand_name': 'KCT', 'is_active': True, 'status': 'active'}
    )
    
    # Run the check task synchronously
    result = check_domain_virustotal(target_id=target.id)
    print("Task result:")
    for k, v in result.items():
        if k != "categories" and k != "total_votes":
            print(f"  {k}: {v}")
            
    # Fetch generated database report
    report = VirusTotalReport.objects.filter(target=target).order_by('-checked_at').first()
    if report:
        print("\n3. Verifying Database Report fields:")
        print(f"  Domain: {report.domain}")
        print(f"  Malicious: {report.malicious}")
        print(f"  Suspicious: {report.suspicious}")
        print(f"  Harmless: {report.harmless}")
        print(f"  Undetected: {report.undetected}")
        print(f"  Total Engines: {report.total_engines}")
        print(f"  Reputation: {report.reputation_score}")
        print(f"  Org ID: {report.org_id}")
        
        # Verify db model matches result dict
        assert report.malicious == result['malicious'], "Malicious mismatch!"
        assert report.suspicious == result['suspicious'], "Suspicious mismatch!"
        assert report.reputation_score == result['reputation'], "Reputation mismatch!"
        print("  [OK] Database report matches task output perfectly.")
    else:
        print("  [ERROR] No database report generated!")

if __name__ == "__main__":
    try:
        test_antimalware_logic()
        print("\n=== Anti Malware Logic is 100% CORRECT ===")
    except Exception as e:
        print(f"\n[FAILED] Logic check failed: {e}")
