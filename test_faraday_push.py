import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import VulnerabilityResult, AttackSurfaceScan
from attacksurface.faraday_import import import_vulnerabilities_to_faraday

scan = AttackSurfaceScan.objects.filter(target="kct.ac.in").last()
print(f"Scan {scan.id} for {scan.target}")
db_vulns = VulnerabilityResult.objects.filter(scan_id=scan.id)
print(f"Found {db_vulns.count()} vulns in DB")

if db_vulns.exists():
    asm_vulns = []
    for v in db_vulns:
        asm_vulns.append({
            "id": v.id,
            "vulnerability_id": v.vulnerability_id or "",
            "domain": v.domain or "",
            "subdomain": v.subdomain or "",
            "severity": v.severity or "info",
            "cve": v.cve or "",
            "cwe": v.cwe or "",
            "finding": v.finding or "",
            "template_id": v.template_id or "",
            "source_tool": v.source_tool or "ASM",
            "discovered_at": str(v.discovered_at) if v.discovered_at else "",
        })
    res = import_vulnerabilities_to_faraday(asm_vulns)
    print(f"Faraday push result: {res}")
