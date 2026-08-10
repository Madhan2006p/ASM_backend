import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import VulnerabilityResult, AttackSurfaceScan
from attacksurface.faraday_import import _insert_vulnerability, _get_faraday_pg_connection, _get_or_create_host
import json

scan = AttackSurfaceScan.objects.last()
db_vulns = VulnerabilityResult.objects.filter(scan=scan)
conn = _get_faraday_pg_connection()
cur = conn.cursor()
cur.execute("SELECT id FROM workspace WHERE name = 'nuclei-asm'")
workspace_id = cur.fetchone()[0]

vuln = db_vulns[0]
v_dict = {
    "vulnerability_id": vuln.vulnerability_id or "",
    "domain": vuln.domain or "",
    "subdomain": vuln.subdomain or "",
    "severity": vuln.severity or "info",
    "cve": vuln.cve or "",
    "cwe": vuln.cwe or "",
    "finding": vuln.finding or "",
    "template_id": vuln.template_id or "",
    "source_tool": vuln.source_tool or "ASM",
}
host_id = _get_or_create_host(cur, workspace_id, v_dict["subdomain"], v_dict["domain"])
try:
    res = _insert_vulnerability(cur, workspace_id, host_id, v_dict, 1)
    print("Result:", res)
    if not res:
        print("Rowcount was zero. Was there a conflict?")
except Exception as e:
    print("Exception:", e)
