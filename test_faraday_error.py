import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import VulnerabilityResult, AttackSurfaceScan
from attacksurface.faraday_import import _get_faraday_pg_connection, _get_or_create_host, _insert_vulnerability
import json

scan = AttackSurfaceScan.objects.filter(target="kct.ac.in").last()
v = VulnerabilityResult.objects.filter(scan_id=scan.id).first()
if v:
    vuln = {
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
    }
    conn = _get_faraday_pg_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM workspace WHERE name = 'nuclei-asm'")
    workspace_id = cur.fetchone()[0]
    host_id = _get_or_create_host(cur, workspace_id, vuln["subdomain"], vuln["domain"])
    
    # Run _insert_vulnerability with trace
    index = 1
    severity = str(vuln.get("severity") or "info").lower()
    severity_map = {
        "info": "informational", "informational": "informational", "low": "low",
        "medium": "medium", "high": "high", "critical": "critical",
    }
    severity = severity_map.get(severity, "informational")
    title = vuln.get("vulnerability_id") or vuln.get("template_id") or f"ASM Vulnerability {index}"
    description = vuln.get("finding") or vuln.get("description") or ""
    cve = vuln.get("cve") or ""
    cwe = vuln.get("cwe") or ""
    target = vuln.get("subdomain") or vuln.get("domain") or ""
    template_id = vuln.get("template_id") or vuln.get("vulnerability_id") or f"asm-{index}"
    source_tool = vuln.get("source_tool") or "ASM"
    external_id = f"asm-{source_tool}-{target}-{template_id}"

    try:
        cur.execute(
            """INSERT INTO vulnerability (
                workspace_id, external_id, name, type, status, data,
                description, resolution, severity, host_id,
                confirmed, impact_accountability, impact_availability,
                impact_confidentiality, impact_integrity,
                disassociated_manually, issuetracker, tool, method,
                parameters, parameter_name, path, query_string,
                request, response, website, code
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            ON CONFLICT DO NOTHING""",
            (
                workspace_id, external_id, f"[{source_tool}] {title}", "vulnerability", "open",
                json.dumps({"cve": cve or None, "cwe": cwe or None, "source_tool": source_tool, "domain": vuln.get("domain", "")}, default=str),
                description or f"Vulnerability found on {target}", "Review the affected endpoint and apply vendor guidance.",
                severity, host_id, False, False, False, False, False, False, "{}", source_tool, "", "", "", target, "", "", "", target, "",
            ),
        )
        print("Success!")
    except Exception as exc:
        print(f"Exception: {exc}")
