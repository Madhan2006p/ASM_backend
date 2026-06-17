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
        severity = request.data.get("severity", "critical,high,medium,low,info")

        if not target_url or not str(target_url).startswith(("http://", "https://")):
            return Response({"detail": "target_url must start with http:// or https://"}, status=status.HTTP_400_BAD_REQUEST)

        # Locate nuclei.exe in integrated_backend/tools
        base_dir = Path(os.path.abspath(__file__)).parents[1]
        nuclei_path = str(base_dir / "tools" / "nuclei.exe")

        if not os.path.exists(nuclei_path):
            # Fallback to system path
            nuclei_path = shutil.which("nuclei")
            
        if not nuclei_path or not os.path.exists(nuclei_path):
            return Response({"detail": f"Nuclei CLI not found at {nuclei_path}. Install nuclei or provide the path."}, status=status.HTTP_400_BAD_REQUEST)

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        output_path = tmp.name
        tmp.close()

        cmd = [
            nuclei_path,
            "-u", str(target_url),
            "-severity", severity,
            "-jle", output_path,
            "-timeout", "3",
            "-retries", "1",
            "-rate-limit", "150",
            "-concurrency", "100",
            "-duc",
            "-no-stdin",
        ]

        def run_and_stream():
            try:
                # Clear previous findings
                Finding.objects.filter(source_tool="Nuclei").delete()
                yield "[INFO] Cleared previous findings from local database.\n"
            except Exception as e:
                yield f"[WARN] Failed to clear previous findings: {e}\n"

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            for line in iter(process.stdout.readline, ""):
                yield line

            process.stdout.close()
            return_code = process.wait()

            yield f"\n[INFO] Nuclei scan finished with return code {return_code}\n"

            # Parse findings
            output_file = Path(output_path)
            if output_file.exists() and output_file.stat().st_size > 0:
                try:
                    file_bytes = output_file.read_bytes()
                    direct_findings = parse_nuclei_json_lines(file_bytes)
                    for f in direct_findings:
                        Finding.objects.create(**f)
                    yield f"[INFO] Saved {len(direct_findings)} findings in database.\n"
                except Exception as e:
                    yield f"[ERROR] Failed to save scan output: {e}\n"
            else:
                yield "[INFO] No vulnerabilities detected.\n"

            try:
                output_file.unlink(missing_ok=True)
            except Exception:
                pass

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
