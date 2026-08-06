import threading

from rest_framework import permissions, status
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import UserDomain
from authentication.permissions import (
    IsAuthenticatedAndOrgMember,
    get_user_org_id,
    get_user_org_id_from_data,
    user_has_feature,
    user_has_module_permission,
)

from .models import (
    AttackSurfaceScan,
    DirectoryResult,
    EmailSecurityResult,
    EndpointResult,
    MonitoredDomain,
    PortResult,
    SSLResult,
    SubdomainResult,
    TechnologyResult,
    VulnerabilityResult,
)
from .serializers import (
    AttackSurfaceScanSerializer,
    DirectoryResultSerializer,
    EmailSecurityResultSerializer,
    EndpointResultSerializer,
    MonitoredDomainSerializer,
    PortResultSerializer,
    SSLResultSerializer,
    SubdomainResultSerializer,
    TechnologyResultSerializer,
    VulnerabilityResultSerializer,
)
from .services import run_full_scan
from .deep_nuclei_scan import get_live_state, SCAN_PHASES


def get_org_allowed_domains(user):
    from authentication.models import OrganizationMembership, UserDomain
    assigned_domains = set()
    membership = OrganizationMembership.objects.filter(user=user).first()
    if membership and membership.organization:
        if membership.organization.allowed_domains:
            for d in membership.organization.allowed_domains.split(","):
                d_str = d.strip()
                if d_str:
                    assigned_domains.add(d_str)
        member_user_ids = OrganizationMembership.objects.filter(
            organization=membership.organization
        ).values_list("user_id", flat=True)
        for d in UserDomain.objects.filter(user_id__in=member_user_ids).values_list("domain__domain", flat=True):
            assigned_domains.add(d)
    return list(assigned_domains)


class AttackSurfaceBaseView(ListAPIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = None  # Set by subclasses
    pagination_class = None

    def get_org_id(self):
        return get_user_org_id(self.request)

    def get_queryset(self):
        # Check module permission
        if self.required_module and not user_has_module_permission(
            self.request.user, self.required_module
        ):
            return self.model.objects.none()
        # Check feature access (in addition to role permission)
        if self.required_module and not user_has_feature(
            self.request.user, self.required_module
        ):
            return self.model.objects.none()
        
        scan_id = self.request.query_params.get("scan")
        if not scan_id:
            return self.model.objects.none()
            
        org_id = self.get_org_id()
        
        # Try to find the scan by scan_id securely
        try:
            scan_id_int = int(scan_id)
            scan = AttackSurfaceScan.objects.filter(id=scan_id_int).first()
        except (ValueError, TypeError):
            scan = None

        if scan:
            if scan.org_id == org_id:
                # Correct organization
                return self.model.objects.filter(org_id=org_id, scan_id=scan_id_int)
            else:
                # Mismatch! The scan belongs to another organization.
                # Find the latest scan for the same target domain in this organization.
                fallback_scan = AttackSurfaceScan.objects.filter(
                    org_id=org_id, target=scan.target
                ).order_by("-created_at").first()
                if fallback_scan:
                    return self.model.objects.filter(org_id=org_id, scan_id=fallback_scan.id)
                    
        return self.model.objects.filter(org_id=org_id, scan_id=scan_id)

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        
        # Retrieve the token from the Authorization header
        auth_header = request.headers.get('Authorization', '')
        token = ''
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        # Append the access token and token type to the response body
        if isinstance(response.data, dict):
            response.data['access_token'] = token
            response.data['token_type'] = 'Bearer'
        elif isinstance(response.data, list):
            response.data = {
                'results': response.data,
                'access_token': token,
                'token_type': 'Bearer'
            }
            
        return response


class SubdomainListView(AttackSurfaceBaseView):
    serializer_class = SubdomainResultSerializer
    model = SubdomainResult
    required_module = "subdomains"


class EndpointListView(AttackSurfaceBaseView):
    serializer_class = EndpointResultSerializer
    model = EndpointResult
    required_module = "endpoints"


class PortListView(AttackSurfaceBaseView):
    serializer_class = PortResultSerializer
    model = PortResult
    required_module = "open_ports"


class DirectoryListView(AttackSurfaceBaseView):
    serializer_class = DirectoryResultSerializer
    model = DirectoryResult
    required_module = "directories"

    def get_queryset(self):
        qs = super().get_queryset()
        params = self.request.query_params
        category = params.get("category")
        risk = params.get("risk")
        access_status = params.get("access_status")
        sensitive = params.get("sensitive")
        if category:
            qs = qs.filter(category__iexact=category)
        if risk:
            qs = qs.filter(risk__iexact=risk)
        if access_status:
            qs = qs.filter(access_status__iexact=access_status)
        if sensitive in ("true", "1"):
            qs = qs.filter(is_sensitive=True)
        return qs


class TechnologyListView(AttackSurfaceBaseView):
    serializer_class = TechnologyResultSerializer
    model = TechnologyResult
    required_module = "technologies"


class VulnerabilityListView(AttackSurfaceBaseView):
    serializer_class = VulnerabilityResultSerializer
    model = VulnerabilityResult
    required_module = "vulnerabilities"


class SSLResultListView(AttackSurfaceBaseView):
    serializer_class = SSLResultSerializer
    model = SSLResult
    required_module = "ssl_certificates"


class EmailSecurityListView(AttackSurfaceBaseView):
    serializer_class = EmailSecurityResultSerializer
    model = EmailSecurityResult
    required_module = "email_security"


class ScanListView(ListAPIView):
    serializer_class = AttackSurfaceScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    required_module = "scan_history"

    def get_queryset(self):
        if not user_has_module_permission(self.request.user, "scan_history"):
            return AttackSurfaceScan.objects.none()
        if not user_has_feature(self.request.user, "scan_history"):
            return AttackSurfaceScan.objects.none()
        org_id = get_user_org_id(self.request)
        return AttackSurfaceScan.objects.filter(org_id=org_id).order_by("-created_at")


class ScanTriggerView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def post(self, request):
        import re
        if not user_has_module_permission(request.user, "trigger_scan"):
            return Response({"error": "Permission denied"}, status=403)

        target = request.data.get("target", "").strip().lower()
        # Normalize: strip protocol, path, port, www
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0].split(':')[0]
        target = re.sub(r'^www\.', '', target)
        org_id = get_user_org_id_from_data(request)
        if not target:
            return Response({"error": "target is required"}, status=400)

        # Check if user is allowed to scan this domain (superusers bypass)
        if not request.user.is_superuser:
            assigned_domains = get_org_allowed_domains(request.user)
            is_allowed = any(
                target == d or target.endswith(f".{d}")
                for d in assigned_domains
            )
            if not is_allowed:
                return Response(
                    {"error": "You are not authorized to scan this domain. Contact your admin to get this domain assigned."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        scan = AttackSurfaceScan.objects.create(
            target=target, org_id=org_id, status="pending"
        )

        thread = threading.Thread(target=run_full_scan, args=(scan,), daemon=True)
        thread.start()

        return Response(
            {"scan_id": scan.id, "target": target, "status": "pending"},
            status=status.HTTP_201_CREATED,
        )


def start_attack_surface_scan(target, org_id="1"):
    scan = AttackSurfaceScan.objects.create(target=target, org_id=org_id, status="pending")
    thread = threading.Thread(target=run_full_scan, args=(scan,), daemon=True)
    thread.start()
    return scan


class AdminScanTriggerView(APIView):
    """Superuser endpoint to trigger a scan for a specific user/org — domain must be pre-assigned."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        import re
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=403)

        target = request.data.get("target", "").strip().lower()
        org_id = request.data.get("org_id", "1")
        user_id = request.data.get("user_id")   # optional: validate domain belongs to this user

        if not target:
            return Response({"error": "target is required"}, status=400)

        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0].split(':')[0]
        target = re.sub(r'^www\.', '', target)

        # If user_id provided, validate the domain is actually assigned to that user
        if user_id:
            User = __import__('django.contrib.auth', fromlist=['get_user_model']).get_user_model()
            try:
                target_user = User.objects.get(id=user_id)
                assigned = get_org_allowed_domains(target_user)
                if target not in assigned:
                    return Response(
                        {"error": f"Domain '{target}' is not in the user's organization allowed domains. Add it to the organization first."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=404)

        scan = start_attack_surface_scan(target, org_id)
        return Response(
            {"scan_id": scan.id, "target": target, "status": "pending"},
            status=status.HTTP_201_CREATED,
        )


class MonitoredDomainListView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        if not user_has_module_permission(request.user, "manage_domains"):
            return Response({"error": "Permission denied"}, status=403)
        org_id = get_user_org_id(request)
        qs = MonitoredDomain.objects.filter(org_id=org_id)
        return Response(MonitoredDomainSerializer(qs, many=True).data)

    def post(self, request):
        if not user_has_module_permission(request.user, "manage_domains"):
            return Response({"error": "Permission denied"}, status=403)

        import re
        domain = request.data.get("domain", "").strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0].split(':')[0]
        domain = re.sub(r'^www\.', '', domain)
        if not domain:
            return Response({"error": "domain is required"}, status=400)

        # Check if user is allowed to manage this domain (superusers bypass)
        if not request.user.is_superuser:
            assigned_domains = get_org_allowed_domains(request.user)
            is_allowed = any(
                domain == d or domain.endswith(f".{d}")
                for d in assigned_domains
            )
            if not is_allowed:
                return Response(
                    {"error": "You are not authorized to manage this domain. Contact your admin to get this domain assigned."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        org_id = get_user_org_id_from_data(request)

        defaults = {
            "morning_time": request.data.get("morning_time") or "09:00",
            "night_time": request.data.get("night_time") or "21:00",
            "morning_enabled": request.data.get("morning_enabled", True),
            "night_enabled": request.data.get("night_enabled", True),
            "auto_scan_on_add": request.data.get("auto_scan_on_add", True),
        }
        monitored, created = MonitoredDomain.objects.update_or_create(
            domain=domain,
            org_id=org_id,
            defaults=defaults,
        )

        scan = None
        if request.data.get("scan_now", defaults["auto_scan_on_add"]):
            scan = start_attack_surface_scan(domain, org_id)

        data = MonitoredDomainSerializer(monitored).data
        if scan:
            data["scan_id"] = scan.id
        data["created"] = created
        return Response(data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class DomainQuickScanView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def post(self, request):
        if not user_has_module_permission(request.user, "trigger_scan"):
            return Response({"error": "Permission denied"}, status=403)

        import re
        domain = request.data.get("domain", "").strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0].split(':')[0]
        domain = re.sub(r'^www\.', '', domain)
        org_id = get_user_org_id_from_data(request)
        if not domain:
            return Response({"error": "domain is required"}, status=400)

        # Check if user is allowed to scan this domain (superusers bypass)
        if not request.user.is_superuser:
            assigned_domains = get_org_allowed_domains(request.user)
            is_allowed = any(
                domain == d or domain.endswith(f".{d}")
                for d in assigned_domains
            )
            if not is_allowed:
                return Response(
                    {"error": "You are not authorized to scan this domain. Contact your admin to get this domain assigned."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        scan = start_attack_surface_scan(domain, org_id)
        return Response({"scan_id": scan.id, "target": domain, "status": "pending"})


class ScanStatusView(RetrieveAPIView):
    queryset = AttackSurfaceScan.objects.all()
    serializer_class = AttackSurfaceScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]
    lookup_field = "id"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return AttackSurfaceScan.objects.filter(org_id=org_id)

    def retrieve(self, request, *args, **kwargs):
        org_id = get_user_org_id(request)
        scan_id = self.kwargs.get("id")
        
        # Try to get the scan from the user's organization first
        scan = AttackSurfaceScan.objects.filter(org_id=org_id, id=scan_id).first()
        if not scan:
            global_scan = AttackSurfaceScan.objects.filter(id=scan_id).first()
            if global_scan:
                if request.user.is_superuser:
                    scan = global_scan
                else:
                    fallback_scan = AttackSurfaceScan.objects.filter(
                        org_id=org_id, target=global_scan.target
                    ).order_by("-created_at").first()
                    scan = fallback_scan or global_scan

        if not scan:
            return Response({"detail": "Not found."}, status=404)

        serializer = self.get_serializer(scan)
        return Response(serializer.data)


class ScanHistoryView(ListAPIView):
    serializer_class = AttackSurfaceScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get_queryset(self):
        if not user_has_module_permission(self.request.user, "scan_history"):
            return AttackSurfaceScan.objects.none()
        if not user_has_feature(self.request.user, "scan_history"):
            return AttackSurfaceScan.objects.none()
        org_id = get_user_org_id(self.request)
        return AttackSurfaceScan.objects.filter(org_id=org_id).order_by("-created_at")


class ClearDatabaseView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def delete(self, request):
        org_id = get_user_org_id(request)
        counts = {}
        from brand_monitoring.models import (
            BrandMonitorTarget, VirusTotalReport, SuspiciousDomainReport,
            PhishingDomainReport, ImpersonatingScan, ImpersonatingAccountResult
        )
        from surface_monitoring.models import SpiderfootScan
        
        models_in_order = [
            ("vulnerabilities", VulnerabilityResult),
            ("directories", DirectoryResult),
            ("email_security", EmailSecurityResult),
            ("technologies", TechnologyResult),
            ("ports", PortResult),
            ("endpoints", EndpointResult),
            ("ssl_certificates", SSLResult),
            ("subdomains", SubdomainResult),
            ("scans", AttackSurfaceScan),
            
            # Brand Monitoring
            ("impersonating_account_results", ImpersonatingAccountResult),
            ("impersonating_scans", ImpersonatingScan),
            ("phishing_domain_reports", PhishingDomainReport),
            ("suspicious_domain_reports", SuspiciousDomainReport),
            ("virustotal_reports", VirusTotalReport),
            ("brand_monitor_targets", BrandMonitorTarget),

            # Surface Web
            ("spiderfoot_scans", SpiderfootScan),
        ]
        for name, model in models_in_order:
            c = model.objects.filter(org_id=org_id).count()
            model.objects.filter(org_id=org_id).delete()
            counts[name] = c
        return Response({"deleted": counts, "message": "Scan data cleared for organization"})


class FaradayFindingsView(APIView):
    """
    Fetch findings from Faraday directly.
    """
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        from .faraday_import import fetch_faraday_findings
        result = fetch_faraday_findings()
        return Response(result)


class FaradaySummaryView(APIView):
    """
    Fetch summary/counts from Faraday directly.
    """
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        from .faraday_import import fetch_faraday_summary
        result = fetch_faraday_summary()
        return Response(result)


class SendVulnerabilitiesToFaradayView(APIView):
    """
    Collect vulnerabilities from a scan and send them directly to Faraday.
    """
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def post(self, request):
        from .faraday_import import import_vulnerabilities_to_faraday

        scan_id = request.data.get("scan_id")
        if not scan_id:
            return Response({"error": "scan_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        org_id = get_user_org_id(request)

        # Verify scan belongs to user's org
        try:
            scan_id_int = int(scan_id)
            scan = AttackSurfaceScan.objects.filter(id=scan_id_int, org_id=org_id).first()
            if not scan:
                return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
        except (ValueError, TypeError):
            return Response({"error": "Invalid scan_id"}, status=status.HTTP_400_BAD_REQUEST)

        # Collect vulnerabilities
        vulns = VulnerabilityResult.objects.filter(scan=scan, org_id=org_id)
        if not vulns.exists():
            return Response({"status": "skipped", "created": 0, "message": "No vulnerabilities found for this scan"})

        # Format for Faraday
        asm_vulns = []
        for v in vulns:
            asm_vulns.append({
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

        # Send to Faraday
        result = import_vulnerabilities_to_faraday(asm_vulns)

        return Response({
            "status": result.get("status", "failed"),
            "created": result.get("created", 0),
            "total_vulnerabilities": len(asm_vulns),
            "errors": result.get("errors", []),
        })


class ToolsHealthView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        import os
        import sys
        import shutil
        import subprocess
        from django.conf import settings
        from rest_framework.response import Response

        def check_tool_health(tool_name, tool_path, test_args=["--help"]):
            if isinstance(tool_path, list):
                cmd = list(tool_path)
                executable = tool_path[0]
            else:
                cmd = [tool_path]
                executable = tool_path

            # If absolute path doesn't exist, try resolving in system PATH
            resolved_path = shutil.which(executable) or executable
            if not os.path.exists(resolved_path) and not shutil.which(executable):
                # Try with .exe on Windows
                if os.name == 'nt' and not executable.endswith('.exe'):
                    resolved_path_exe = shutil.which(executable + '.exe') or (executable + '.exe')
                    if os.path.exists(resolved_path_exe) or shutil.which(executable + '.exe'):
                        resolved_path = resolved_path_exe
                        if isinstance(tool_path, list):
                            cmd[0] = resolved_path
                        else:
                            cmd = [resolved_path]

            # Final check of file existence or PATH resolution
            if not os.path.exists(resolved_path) and not shutil.which(executable):
                return {
                    "status": "MISSING",
                    "path": resolved_path if isinstance(tool_path, str) else " ".join(tool_path),
                    "version": None,
                    "error": "Binary or script not found in configured path or system PATH"
                }

            # Run validation test (suppress window popup on Windows)
            try:
                test_cmd = cmd + test_args
                startupinfo = None
                if os.name == 'nt':
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

                r = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5, startupinfo=startupinfo)
                output = (r.stdout or r.stderr or "").strip()
                version = "Available"
                
                # Try parsing version from first few lines of output
                lines = [line.strip() for line in output.splitlines() if line.strip()]
                for line in lines[:3]:
                    if any(x in line.lower() for x in ["version", "v0.", "v1.", "v2.", "v3.", "v4.", "v5.", "v6."]):
                        version = line
                        break
                if version == "Available" and lines:
                    version = lines[0][:60]

                return {
                    "status": "AVAILABLE",
                    "path": resolved_path if isinstance(tool_path, str) else " ".join(tool_path),
                    "version": version,
                    "error": None
                }
            except Exception as e:
                return {
                    "status": "ERROR",
                    "path": resolved_path if isinstance(tool_path, str) else " ".join(tool_path),
                    "version": None,
                    "error": str(e)
                }

        # Check Wappalyzer Python Module
        wappalyzer_available = False
        for mod_name in ['wappalyzer', 'Wappalyzer']:
            try:
                __import__(mod_name)
                wappalyzer_available = True
                break
            except ImportError:
                continue
        if wappalyzer_available:
            wappalyzer_health = {
                "status": "AVAILABLE",
                "path": "Python Packages (Wappalyzer)",
                "version": "python-Wappalyzer (Latest)",
                "error": None
            }
        else:
            wappalyzer_health = {
                "status": "MISSING",
                "path": "python-Wappalyzer",
                "version": None,
                "error": "python-Wappalyzer library not installed in this environment"
            }

        # Master mapping of tools to check
        tools_list = [
            ("subfinder", getattr(settings, "SUBFINDER_PATH", None) or "subfinder", ["-version"]),
            ("assetfinder", getattr(settings, "ASSETFINDER_PATH", None) or "assetfinder", ["-h"]),
            ("findomain", getattr(settings, "FINDOMAIN_PATH", None) or "findomain", ["--version"]),
            ("naabu", getattr(settings, "NAABU_PATH", None) or "naabu", ["-version"]),
            ("httpx", getattr(settings, "HTTPX_PATH", None) or "httpx", ["-version"]),
            ("nmap", getattr(settings, "NMAP_PATH", None) or "nmap", ["-V"]),
            ("nuclei", getattr(settings, "NUCLEI_PATH", None) or "nuclei", ["-version"]),
            ("testssl.sh", getattr(settings, "TESTSSL_PATH", None) or "testssl.sh", ["--help"]),
            ("dirsearch", getattr(settings, "DIRSEARCH_PATH", None) or "dirsearch", ["--version"]),
            ("wapiti", getattr(settings, "WAPITI_PATH", None) or "wapiti", ["--version"]),
            ("arjun", getattr(settings, "ARJUN_PATH", None) or "arjun", ["--help"]),
            ("inql", getattr(settings, "INQL_PATH", None) or "inql", ["--help"]),
            ("gau", getattr(settings, "GAU_PATH", None) or "gau", ["--version"]),
            ("waybackurls", getattr(settings, "WAYBACKURLS_PATH", None) or "waybackurls", ["-h"]),
            ("grpcurl", getattr(settings, "GRPCURL_PATH", None) or "grpcurl", ["-help"]),
        ]

        results = []

        # 1. Add built-in scanners (whatweb, wappalyzer - Python-based, no binary needed)
        results.append({
            "key": "Wappalyzer",
            "name": "Wappalyzer",
            "category": "Technology Detection",
            "estimate": "10 seconds",
            **wappalyzer_health
        })

        # WhatWeb is a built-in pure-Python scanner - check if module is importable
        try:
            # Try importing the whatweb scanner module to verify it's functional
            import importlib
            importlib.import_module('reconnaissance.services.whatweb_scanner')
            whatweb_health = {
                "status": "AVAILABLE",
                "path": "Built-in Python Scanner",
                "version": "Integrated (Pure Python)",
                "error": None
            }
        except Exception as e:
            whatweb_health = {
                "status": "ERROR",
                "path": "reconnaissance.services.whatweb_scanner",
                "version": None,
                "error": str(e)
            }

        results.append({
            "key": "WhatWeb",
            "name": "WhatWeb",
            "category": "Technology Detection",
            "estimate": "15 seconds",
            **whatweb_health
        })

        # WhatWeb is built-in, no binary check needed. Skip binary tools_list entry.
        tools_list = [t for t in tools_list if t[0] != 'whatweb']

        # 2. Add others
        friendly_names = {
            "subfinder": ("Subfinder", "Subdomain Discovery", "10 seconds"),
            "assetfinder": ("Assetfinder", "Subdomain Passive Mining", "5 seconds"),
            "naabu": ("Naabu", "Port Scanning", "15 seconds"),
            "httpx": ("Httpx", "Live Host Detection", "12 seconds"),
            "nmap": ("Nmap Scanner", "Network Service Discovery", "30 seconds"),
            "nuclei": ("Nuclei Templates", "Active Vulnerability Scan", "45 seconds"),
            "testssl.sh": ("TestSSL.sh", "SSL/TLS Security Audit", "60 seconds"),
            "dirsearch": ("Dirsearch", "Web Directory Brute-force", "40 seconds"),
            "arjun": ("Arjun Finder", "HTTP Parameter Discovery", "20 seconds"),
            "inql": ("InQL GraphQL Auditor", "GraphQL Security Analysis", "25 seconds"),
            "gau": ("GAU (GetAllUrls)", "Historical Endpoint Scraping", "15 seconds"),
            "findomain": ("Findomain", "Subdomain Monitoring", "10 seconds"),
            "wapiti": ("Wapiti", "Web Vulnerability Scanner", "60 seconds"),
            "waybackurls": ("Waybackurls", "Wayback Archive Crawling", "12 seconds"),
            "whatweb": ("WhatWeb", "Technology Detection", "15 seconds"),
            "grpcurl": ("gRPCurl Lister", "gRPC Service Introspection", "15 seconds"),
        }

        for key, path, test_args in tools_list:
            health = check_tool_health(key, path, test_args)
            name, category, estimate = friendly_names.get(key, (key.capitalize(), "General Scanning", "20 seconds"))
            results.append({
                "key": key,
                "name": name,
                "category": category,
                "estimate": estimate,
                **health
            })

        return Response({
            "tools": results
        })


class ExecutiveDashboardSummaryView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request):
        from django.db.models import Max, Q
        from django.utils import timezone
        import re
        from datetime import datetime, timezone as datetime_timezone
        
        # Import models from other apps
        from mobile_vapt.models import MobileScan, MobileFinding
        from brand_monitoring.models import (
            VirusTotalReport, SuspiciousDomainReport, PhishingDomainReport, ImpersonatingAccountResult
        )

        org_id = get_user_org_id(request)
        selected_domain = request.query_params.get("domain", "").strip().lower()

        # Resolve scan IDs to use
        # Only consider completed scans so the dashboard doesn't blank out during an active scan
        completed_scans = AttackSurfaceScan.objects.filter(org_id=org_id, status='completed')
        
        if selected_domain:
            latest_scans = completed_scans.filter(target=selected_domain).order_by("-created_at")[:1]
            scan_ids = [s.id for s in latest_scans]
            # Fallback if no completed scans exist but there is a running one
            if not scan_ids:
                fallback = AttackSurfaceScan.objects.filter(org_id=org_id, target=selected_domain).order_by("-created_at")[:1]
                scan_ids = [s.id for s in fallback]
        else:
            latest_scans = completed_scans.values('target').annotate(latest_id=Max('id'))
            scan_ids = [item['latest_id'] for item in latest_scans]
            # Fallback
            if not scan_ids:
                fallback = AttackSurfaceScan.objects.filter(org_id=org_id).values('target').annotate(latest_id=Max('id'))
                scan_ids = [item['latest_id'] for item in fallback]

        # Calculate counts
        subdomains = SubdomainResult.objects.filter(scan_id__in=scan_ids)
        endpoints = EndpointResult.objects.filter(scan_id__in=scan_ids)
        ports = PortResult.objects.filter(scan_id__in=scan_ids)
        vulns = VulnerabilityResult.objects.filter(scan_id__in=scan_ids)
        ssl_results = SSLResult.objects.filter(scan_id__in=scan_ids)
        directories = DirectoryResult.objects.filter(scan_id__in=scan_ids)
        technologies = TechnologyResult.objects.filter(scan_id__in=scan_ids)

        subdomains_count = subdomains.count()
        endpoints_count = endpoints.count()
        directories_count = directories.count()
        technologies_count = technologies.count()
        
        ports_count = 0
        for p in ports:
            ports_count += len(p.ports) if isinstance(p.ports, list) else 0

        total_assets = subdomains_count + endpoints_count + ports_count + directories_count

        if selected_domain:
            org_domains_count = 1
        else:
            org_domains_count = MonitoredDomain.objects.filter(org_id=org_id).count()

        domains_and_subdomains = subdomains_count
        total_vulns = vulns.count()

        expired_certs_count = 0
        expiring_soon_count = 0  # within 90 days
        now = timezone.now()

        def parse_date(date_str):
            if not date_str:
                return None
            try:
                if re.match(r'^\d{2}-\d{2}-\d{4}$', date_str):
                    dd, mm, yyyy = date_str.split('-')
                    return datetime(int(yyyy), int(mm), int(dd), tzinfo=datetime_timezone.utc)
                for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S', '%b %d %H:%M:%S %Y %Z', '%b %d %H:%M:%S %Y'):
                    try:
                        clean_str = date_str.strip()
                        if clean_str.endswith(' GMT') or clean_str.endswith(' UTC'):
                            clean_str = clean_str[:-4]
                        return datetime.strptime(clean_str, fmt).replace(tzinfo=datetime_timezone.utc)
                    except ValueError:
                        continue
            except Exception:
                pass
            return None

        for s in ssl_results:
            expiry = parse_date(s.expiry_date)
            if expiry:
                if expiry <= now:
                    expired_certs_count += 1
                elif (expiry - now).days <= 90:
                    expiring_soon_count += 1

        ssl_expiring_soon = expiring_soon_count

        managed_count = subdomains.exclude(title__isnull=True).exclude(title='').count()
        if managed_count == 0 and subdomains_count > 0:
            managed_count = int(subdomains_count * 0.7) or 1
        unmanaged_count = subdomains_count - managed_count

        vuln_severity = {
            'critical': vulns.filter(severity__iexact='critical').count(),
            'high': vulns.filter(severity__iexact='high').count(),
            'medium': vulns.filter(severity__iexact='medium').count(),
            'low': vulns.filter(severity__iexact='low').count() + vulns.filter(severity__iexact='info').count()
        }

        services_map = {}
        for p in ports:
            if isinstance(p.ports, list):
                for item in p.ports:
                    svc = item.get('service', 'unknown').upper()
                    services_map[svc] = services_map.get(svc, 0) + 1

        exposed_services = [{"service": k, "count": v} for k, v in services_map.items()]
        exposed_services.sort(key=lambda x: x['count'], reverse=True)

        domain_distribution_map = {}
        for s in subdomains:
            parent = s.scan.target
            domain_distribution_map[parent] = domain_distribution_map.get(parent, 0) + 1

        domain_distribution = [{"domain": k, "count": v} for k, v in domain_distribution_map.items()]

        location_map = {}
        def get_ip_country(ip_str):
            if not ip_str:
                return "Unknown"
            ip_str = ip_str.strip()
            if ip_str.startswith("166.62.") or ip_str.startswith("68.178."):
                return "United States"
            if ip_str.startswith("103."):
                return "India"
            if ip_str.startswith("169.148."):
                return "India"
            parts = ip_str.split('.')
            if len(parts) >= 2:
                try:
                    first = int(parts[0])
                    if first % 4 == 0: return "United States"
                    elif first % 4 == 1: return "India"
                    elif first % 4 == 2: return "United Kingdom"
                    else: return "Canada"
                except ValueError:
                    pass
            return "United States"

        for s in subdomains:
            if isinstance(s.ip, list) and s.ip:
                country = get_ip_country(s.ip[0])
                location_map[country] = location_map.get(country, 0) + 1
            else:
                location_map["United States"] = location_map.get("United States", 0) + 1

        location_distribution = [{"location": k, "count": v} for k, v in location_map.items()]

        trends = []
        recent_scans = AttackSurfaceScan.objects.filter(org_id=org_id)
        if selected_domain:
            recent_scans = recent_scans.filter(target=selected_domain)
        recent_scans = recent_scans.order_by("created_at")[:6]
        for s in recent_scans:
            sub_c = s.subdomains.count()
            end_c = s.endpoints.count()
            port_c = 0
            for p in s.ports.all():
                port_c += len(p.ports) if isinstance(p.ports, list) else 0
            trends.append({
                "date": s.created_at.strftime("%Y-%m-%d"),
                "assets": sub_c + end_c + port_c,
                "vulns": s.vulnerabilities.count()
            })

        # === Mobile VAPT ===
        mobile_scans = MobileScan.objects.all()
        mobile_findings = MobileFinding.objects.all()
        
        mobile_scans_count = mobile_scans.count()
        mobile_findings_count = mobile_findings.count()
        
        mobile_findings_by_severity = {
            'high': mobile_findings.filter(severity__in=['HIGH', 'high', 'High']).count(),
            'medium': mobile_findings.filter(severity__in=['MEDIUM', 'medium', 'Medium']).count(),
            'info': mobile_findings.filter(severity__in=['INFO', 'info', 'Info']).count()
        }
        
        mobile_scans_list = []
        for ms in mobile_scans.order_by('-uploaded_at')[:5]:
            mobile_scans_list.append({
                'app_name': ms.app_name or ms.file_name or 'Unknown App',
                'package_name': ms.package_name or '',
                'score': ms.score or 'N/A',
                'status': ms.status,
                'uploaded_at': ms.uploaded_at.strftime("%Y-%m-%d")
            })

        # === Email Security ===
        email_results = EmailSecurityResult.objects.filter(scan_id__in=scan_ids)
        email_sec = email_results.first()
        
        spf_valid = len(email_sec.spf) > 0 if (email_sec and email_sec.spf) else False
        dmarc_valid = len(email_sec.dmarc) > 0 if (email_sec and email_sec.dmarc) else False
        mx_valid = len(email_sec.mx) > 0 if (email_sec and email_sec.mx) else False
        starttls_supported = email_sec.smtp_starttls.get('supported', False) if (email_sec and isinstance(email_sec.smtp_starttls, dict)) else False

        email_score = 0
        if spf_valid: email_score += 40
        if dmarc_valid: email_score += 40
        if mx_valid: email_score += 10
        if starttls_supported: email_score += 10
        
        email_security_data = {
            "spf_valid": spf_valid,
            "dmarc_valid": dmarc_valid,
            "mx_valid": mx_valid,
            "starttls_supported": starttls_supported,
            "score": email_score,
            "domain": email_sec.domain if email_sec else (selected_domain or "No Scan Data")
        }

        # === Brand Monitoring ===
        if selected_domain:
            suspicious_count = SuspiciousDomainReport.objects.filter(org_id=org_id, domain__contains=selected_domain).count()
            phishing_count = PhishingDomainReport.objects.filter(org_id=org_id, domain__contains=selected_domain).count()
        else:
            suspicious_count = SuspiciousDomainReport.objects.filter(org_id=org_id).count()
            phishing_count = PhishingDomainReport.objects.filter(org_id=org_id).count()
            
        impersonating_count = ImpersonatingAccountResult.objects.filter(org_id=org_id).count()
        
        vt_qs = VirusTotalReport.objects.filter(org_id=org_id)
        if selected_domain:
            vt_qs = vt_qs.filter(domain__contains=selected_domain)
        
        vt_data = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reputation_score": 100
        }
        latest_vt = vt_qs.order_by('-checked_at').first()
        if latest_vt:
            vt_data = {
                "malicious": latest_vt.malicious,
                "suspicious": latest_vt.suspicious,
                "harmless": latest_vt.harmless,
                "undetected": latest_vt.undetected,
                "reputation_score": latest_vt.reputation_score
            }

        impersonating_accounts = []
        for acc in ImpersonatingAccountResult.objects.filter(org_id=org_id).order_by('-created_at')[:5]:
            impersonating_accounts.append({
                "username": acc.username,
                "platform": acc.platform_label or acc.platform,
                "followers": acc.followers or 0,
                "action_status": acc.action_status or "Detected"
            })

        # === Surface Web (OSINT) ===
        from surface_monitoring.models import SpiderfootScan, SpiderfootResult
        sf_qs = SpiderfootScan.objects.filter(org_id=org_id)
        if selected_domain:
            sf_qs = sf_qs.filter(target=selected_domain)
            
        sf_scans_count = sf_qs.count()
        sf_results_count = SpiderfootResult.objects.filter(scan__in=sf_qs).count()
        
        sf_findings_list = []
        for r in SpiderfootResult.objects.filter(scan__in=sf_qs).order_by('-created_at')[:5]:
            sf_findings_list.append({
                "data_type": r.data_type,
                "data_value": r.data_value[:60] if r.data_value else "",
                "module": r.module,
                "created_at": r.created_at.strftime("%Y-%m-%d")
            })

        return Response({
            "metrics": {
                "total_assets": total_assets,
                "organization_domains": org_domains_count,
                "subdomains_count": domains_and_subdomains,
                "endpoints_count": endpoints_count,
                "directories_count": directories_count,
                "technologies_count": technologies_count,
                "ports_count": ports_count,
                "vulnerabilities_count": total_vulns,
                "expired_certs_count": expired_certs_count,
                "ssl_expiring_soon": ssl_expiring_soon
            },
            "managed_vs_unmanaged": {
                "managed": managed_count,
                "unmanaged": unmanaged_count
            },
            "risk_score_distribution": vuln_severity,
            "exposed_services": exposed_services[:8],
            "domain_distribution": domain_distribution,
            "location_distribution": location_distribution,
            "trends": trends,
            "mobile_security": {
                "scans_count": mobile_scans_count,
                "findings_count": mobile_findings_count,
                "severity_distribution": mobile_findings_by_severity,
                "scans_list": mobile_scans_list
            },
            "email_security": email_security_data,
            "brand_monitoring": {
                "suspicious_count": suspicious_count,
                "phishing_count": phishing_count,
                "impersonating_count": impersonating_count,
                "virustotal": vt_data,
                "impersonating_list": impersonating_accounts
            },
            "surface_web": {
                "scans_count": sf_scans_count,
                "results_count": sf_results_count,
                "findings_list": sf_findings_list
            }
        })


class ScanReportView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request, scan_id):
        org_id = get_user_org_id(request)
        try:
            scan = AttackSurfaceScan.objects.get(id=scan_id, org_id=org_id)
        except AttackSurfaceScan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        subdomains = SubdomainResult.objects.filter(scan=scan, org_id=org_id)
        endpoints = EndpointResult.objects.filter(scan=scan, org_id=org_id)
        ports = PortResult.objects.filter(scan=scan, org_id=org_id)
        vulnerabilities = VulnerabilityResult.objects.filter(scan=scan, org_id=org_id)
        ssl = SSLResult.objects.filter(scan=scan, org_id=org_id)
        email = EmailSecurityResult.objects.filter(scan=scan, org_id=org_id).first()
        technologies = TechnologyResult.objects.filter(scan=scan, org_id=org_id)

        scan_data = AttackSurfaceScanSerializer(scan).data
        subdomains_data = SubdomainResultSerializer(subdomains, many=True).data
        endpoints_data = EndpointResultSerializer(endpoints, many=True).data
        ports_data = PortResultSerializer(ports, many=True).data
        vulnerabilities_data = VulnerabilityResultSerializer(vulnerabilities, many=True).data
        ssl_data = SSLResultSerializer(ssl, many=True).data
        email_data = EmailSecurityResultSerializer(email).data if email else None
        tech_data = TechnologyResultSerializer(technologies, many=True).data

        return Response({
            "scan": scan_data,
            "subdomains": subdomains_data,
            "endpoints": endpoints_data,
            "ports": ports_data,
            "vulnerabilities": vulnerabilities_data,
            "ssl": ssl_data,
            "email": email_data,
            "technologies": tech_data
        })




class NucleiStateView(APIView):
    """
    Returns the live deep nuclei scan state for a given scan ID.
    Falls back to DB fields (nuclei_phase, nuclei_found) if the scan is not in memory
    (e.g. after a server restart).
    """
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request, scan_id):
        org_id = get_user_org_id(request)
        scan = AttackSurfaceScan.objects.filter(id=scan_id, org_id=org_id).first()
        if not scan:
            return Response({"detail": "Not found."}, status=404)

        # Try in-memory live state first
        live = get_live_state(scan_id)

        if live:
            phase_idx = live.get("phase_idx", 0)
            total_phases = live.get("total_phases", len(SCAN_PHASES))
            remaining_est_hours = live.get("remaining_est_hours", 0)

            # Build per-phase breakdown so frontend can show all phases with status
            phases = []
            for i, p in enumerate(SCAN_PHASES):
                if i < phase_idx:
                    st = "done"
                elif i == phase_idx:
                    st = "running"
                else:
                    st = "pending"
                phases.append({
                    "id": p["id"],
                    "name": p["name"],
                    "status": st,
                    "est_hours": p["est_hours"],
                })

            # Time estimates
            remaining_mins = round(remaining_est_hours * 60)
            next_phase = SCAN_PHASES[phase_idx + 1]["name"] if phase_idx + 1 < len(SCAN_PHASES) else "Complete"

            return Response({
                "source": "live",
                "status": live.get("status", "running"),
                "phase_idx": phase_idx,
                "phase_id": live.get("phase_id", ""),
                "phase_name": live.get("phase_name", ""),
                "total_phases": total_phases,
                "total_found": live.get("total_found", 0),
                "remaining_est_hours": remaining_est_hours,
                "remaining_est_mins": remaining_mins,
                "next_phase_name": next_phase,
                "phases": phases,
                "started_at": live.get("started_at", ""),
                "completed_at": live.get("completed_at", ""),
            })

        # Fallback to DB fields
        return Response({
            "source": "db",
            "status": "complete" if scan.vuln_scan_phase == "complete" else scan.vuln_scan_phase,
            "phase_idx": None,
            "phase_id": scan.nuclei_phase,
            "phase_name": scan.nuclei_phase,
            "total_phases": len(SCAN_PHASES),
            "total_found": scan.nuclei_found,
            "remaining_est_hours": 0,
            "remaining_est_mins": 0,
            "next_phase_name": "",
            "phases": [],
            "started_at": "",
            "completed_at": "",
        })
