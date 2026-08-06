import os
import shutil
import tempfile
import subprocess
import json
from pathlib import Path
from django.http import StreamingHttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from authentication.permissions import IsAuthenticatedAndOrgMember

from .models import Finding

# Simple mapping of severity
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

def parse_nuclei_json_lines(file_bytes: bytes) -> list:
    lines = file_bytes.decode("utf-8", errors="ignore").strip().split('\n')
    findings = []
    seen = set()
    base_id = 2000000000  # Arbitrary high ID for direct nuclei findings
    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            info = data.get('info', {})
            severity = str(info.get('severity', 'info')).capitalize()
            # Extract CVE if available
            cve = ''
            cwe = ''
            classification = info.get('classification', {})
            cve_list = classification.get('cve-id')
            cwe_list = classification.get('cwe-id')
            if cve_list:
                cve = cve_list[0] if isinstance(cve_list, list) else str(cve_list)
            if cwe_list:
                cwe = cwe_list[0] if isinstance(cwe_list, list) else str(cwe_list)

            title = info.get('name') or data.get('template-id', 'Unknown Nuclei Finding')
            endpoint = data.get('matched-at') or data.get('host') or ""
            
            key = (title, endpoint, severity)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "defectdojo_finding_id": base_id + idx,
                "title": title,
                "severity": severity,
                "cve": cve,
                "cwe": cwe,
                "description": info.get('description') or f"Found by template: {data.get('template-id')}",
                "mitigation": info.get('remediation') or info.get('recommendation') or "",
                "endpoint": endpoint,
                "active": True,
                "date_found": data.get('timestamp', ''),
                "source_tool": "Nuclei",
                "status": "opened",
                "detection_time": data.get('timestamp', '')
            })
        except json.JSONDecodeError:
            pass
    return findings

class ClearFindingsView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def delete(self, request):
        Finding.objects.all().delete()
        return Response({"status": "cleared"})


class NucleiScanView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def post(self, request):
        target_url = request.data.get("target_url")
        if not target_url or not str(target_url).startswith(("http://", "https://")):
            return Response({"detail": "target_url must start with http:// or https://"}, status=status.HTTP_400_BAD_REQUEST)

        from urllib.parse import urlparse
        from attacksurface.scanner.vulnerability_scanner import run_python_vuln_scanner

        def run_and_stream():
            try:
                Finding.objects.filter(source_tool="PythonScanner").delete()
                yield "[INFO] Starting Python Vulnerability Scanner...\n"
            except Exception as e:
                yield f"[WARN] Failed to clear previous findings: {e}\n"

            domain = urlparse(target_url).hostname or target_url
            httpx_items = [{"url": target_url, "headers": {}, "status_code": 0}]

            try:
                vulns = run_python_vuln_scanner(domain, httpx_items)
                yield f"[INFO] Discovered {len(vulns)} vulnerabilities using Python Vulnerability Engine.\n"

                base_id = 2000000000
                saved_count = 0
                for idx, v in enumerate(vulns):
                    sev = str(v.get("severity") or "info").capitalize()
                    Finding.objects.create(
                        defectdojo_finding_id=base_id + idx,
                        title=v.get("finding") or "Vulnerability Discovered",
                        severity=sev,
                        cve=v.get("cve") or "",
                        cwe=v.get("cwe") or "",
                        description=v.get("finding") or "",
                        mitigation="Configure recommended security settings.",
                        endpoint=v.get("subdomain") or domain,
                        active=True,
                        source_tool="PythonScanner",
                        status="opened",
                    )
                    saved_count += 1
                    yield f"  [+] Saved finding: {v.get('finding')} [{sev}]\n"

                yield f"\n[INFO] Python vulnerability scan complete. {saved_count} findings recorded.\n"
            except Exception as e:
                yield f"[ERROR] Python scanner failed: {e}\n"

        return StreamingHttpResponse(run_and_stream(), content_type="text/plain")



class FindingsListView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        findings = Finding.objects.all().order_by('-date_found')
        data = []
        seen = set()
        for f in findings:
            key = (f.title, f.endpoint, f.severity)
            if key in seen:
                continue
            seen.add(key)
            data.append({
                "finding_id": f.defectdojo_finding_id,
                "title": f.title,
                "severity": f.severity,
                "cve": f.cve,
                "cwe": f.cwe,
                "description": f.description,
                "mitigation": f.mitigation,
                "endpoint": f.endpoint,
                "active": f.active,
                "date_found": f.date_found.isoformat() if f.date_found else None,
            })
        return Response({"findings": data})


class FindingsSummaryView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        findings = Finding.objects.all()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        seen = set()
        for f in findings:
            key = (f.title, f.endpoint, f.severity)
            if key in seen:
                continue
            seen.add(key)
            sev = str(f.severity).capitalize()
            if sev in counts:
                counts[sev] += 1
        
        total = sum(counts.values())
        score = min(100, counts["Critical"] * 10 + counts["High"] * 5 + counts["Medium"] * 2)
        
        if score >= 50:
            level = "Critical"
        elif score >= 30:
            level = "High"
        elif score >= 15:
            level = "Medium"
        else:
            level = "Low"

        return Response({
            "total_findings": total,
            "critical_count": counts["Critical"],
            "high_count": counts["High"],
            "medium_count": counts["Medium"],
            "low_count": counts["Low"],
            "risk_score": score,
            "risk_level": level,
        })
