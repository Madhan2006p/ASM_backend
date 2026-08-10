import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import django
django.setup()

from attacksurface.models import AttackSurfaceScan, VulnerabilityResult
from owasp_scanner.engine import save_owasp_findings

# Reuse the latest scan for hackersinfotech.com if present
scan = AttackSurfaceScan.objects.filter(target='hackersinfotech.com').order_by('-created_at').first()
if not scan:
    scan = AttackSurfaceScan.objects.create(target='hackersinfotech.com', org_id='1', status='completed')

# Simulate a couple of OWASP findings
fake_findings = [
    {
        "vulnerability_id": "A05-SERVER-FINGERPRINT",
        "domain": "hackersinfotech.com",
        "subdomain": "hackersinfotech.com",
        "severity": "LOW",
        "cve": "",
        "cwe": "CWE-200",
        "finding": "Server fingerprint disclosed",
        "description": "Server header reveals software.",
        "remediation": "Suppress Server header.",
        "reference": "https://owasp.org/",
        "template_id": "misconfig/server-fingerprint",
        "source_tool": "OWASP Top 10",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_rank": 5,
    },
]

saved = save_owasp_findings(scan, fake_findings, "hackersinfotech.com")
print(f"saved={saved}", flush=True)

row = VulnerabilityResult.objects.filter(scan=scan, vulnerability_id="A05-SERVER-FINGERPRINT").first()
if row:
    print(f"row: owasp_category={row.owasp_category!r} owasp_rank={row.owasp_rank} source_tool={row.source_tool!r}", flush=True)
else:
    print("row NOT FOUND", flush=True)
