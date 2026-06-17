from concurrent.futures import ThreadPoolExecutor

from rest_framework import permissions
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.permissions import (
    HasModulePermission,
    IsAuthenticatedAndOrgMember,
    get_user_org_id,
)

from .models import DiscoveredDomain, ReconEndpoint, ReconScan, ToolOutput
from .serializers import (
    DiscoveredDomainSerializer,
    ReconEndpointSerializer,
    ReconScanSerializer,
    ToolOutputSerializer,
)
from .services.api_inspector import (
    collect_api_urls,
    detect_api_technology,
    test_http_methods,
)
from .services.assetfinder_scanner import run_assetfinder
from .services.command_utils import dedupe_preserve_order, extract_hostnames, normalize_target
from .services.dirsearch_scanner import run_dirsearch
from .services.dns_scanner import query_dns
from .services.email_security_scanner import run_email_security_scan
from .services.findomain_scanner import run_findomain
from .services.gau_scanner import run_gau
from .services.httpx_scanner import run_httpx
from .services.naabu_scanner import run_naabu
from .services.nmap_scanner import run_nmap
from .services.nuclei_scanner import run_nuclei
from .services.subfinder_scanner import run_subfinder
from .services.wappalyzer_scanner import run_wappalyzer
from .services.wapiti_scanner import run_wapiti
from .services.waybackurls_scanner import run_waybackurls
from .services.whatweb_scanner import run_whatweb_scan


class RunScanView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def post(self, request):
        submitted_target = request.data.get("target")
        target = normalize_target(submitted_target)

        if not target:
            return Response({"error": "target is required"}, status=400)

        org_id = get_user_org_id(request)
        scan = ReconScan.objects.create(org_id=org_id, target=target, status="running", progress=5)

        with ThreadPoolExecutor(max_workers=8) as executor:
            discovery_futures = {
                "subfinder": executor.submit(run_subfinder, target),
                "assetfinder": executor.submit(run_assetfinder, target),
                "findomain": executor.submit(run_findomain, target),
                "gau": executor.submit(run_gau, target),
                "naabu": executor.submit(run_naabu, target),
                "email_security": executor.submit(run_email_security_scan, target),
                "waybackurls": executor.submit(run_waybackurls, target),
                "wappalyzer": executor.submit(run_wappalyzer, target),
                "whatweb": executor.submit(run_whatweb_scan, target),
                "dig": executor.submit(query_dns, target),
            }

            discovery_results = {
                name: get_future_result(name, future, target)
                for name, future in discovery_futures.items()
            }

        scan.progress = 45
        scan.save(update_fields=["progress"])

        combined_subdomains = collect_subdomains(
            discovery_results["subfinder"],
            discovery_results["assetfinder"],
            discovery_results["findomain"],
        )

        httpx_inputs = combined_subdomains or [target]
        httpx_result = run_httpx(httpx_inputs)

        scan.progress = 65
        scan.save(update_fields=["progress"])

        live_urls = [
            item["url"]
            for item in httpx_result["parsed_output"].get("live_hosts", [])
            if item.get("url")
        ]

        nmap_targets = extract_hostnames(live_urls) or [target]
        nuclei_targets = live_urls or [target]

        with ThreadPoolExecutor(max_workers=4) as executor:
            nmap_future = executor.submit(run_nmap, nmap_targets)
            nuclei_future = executor.submit(run_nuclei, nuclei_targets)
            wapiti_future = executor.submit(run_wapiti, live_urls)
            dirsearch_future = executor.submit(run_dirsearch, live_urls)

            nmap_result = get_future_result("nmap", nmap_future, target)
            nuclei_result = get_future_result("nuclei", nuclei_future, target)
            wapiti_result = get_future_result("wapiti", wapiti_future, target)
            dirsearch_result = get_future_result("dirsearch", dirsearch_future, target)

        scan.progress = 85
        scan.save(update_fields=["progress"])

        tool_results = {
            "subfinder": discovery_results["subfinder"],
            "assetfinder": discovery_results["assetfinder"],
            "findomain": discovery_results["findomain"],
            "gau": discovery_results["gau"],
            "naabu": discovery_results["naabu"],
            "httpx": httpx_result,
            "nmap": nmap_result,
            "nuclei": nuclei_result,
            "email_security": {
                "raw_output": "",
                "parsed_output": discovery_results["email_security"],
            },
            "waybackurls": discovery_results["waybackurls"],
            "wappalyzer": discovery_results["wappalyzer"],
            "whatweb": discovery_results["whatweb"],
            "wapiti": wapiti_result,
            "dirsearch": dirsearch_result,
            "dig": {
                "raw_output": "",
                "parsed_output": discovery_results["dig"],
            },
        }

        persist_tool_outputs(scan, tool_results)
        persist_domains(scan, target, tool_results)
        persist_endpoints(scan, tool_results)

        scan.progress = 100
        scan.status = "completed"
        scan.save(update_fields=["progress", "status"])

        return Response(
            {
                "scan_id": scan.id,
                "target": target,
                "status": scan.status,
                "progress": scan.progress,
                "public_assets": {
                    "total_discovered_subdomains": len(combined_subdomains),
                    "subdomains": combined_subdomains,
                    "total_live_hosts": httpx_result["parsed_output"].get("total_live_hosts", 0),
                    "live_hosts": httpx_result["parsed_output"].get("live_hosts", []),
                },
                "vulnerability_scan": {
                    "nmap_targets": nmap_result["parsed_output"].get("targets_scanned", []),
                    "nuclei_targets": nuclei_result["parsed_output"].get("targets_scanned", []),
                    "wapiti_targets": wapiti_result["parsed_output"].get("targets_scanned", []),
                },
                "email_security": discovery_results["email_security"],
                "dig": discovery_results["dig"],
                "subfinder": tool_results["subfinder"]["parsed_output"],
                "assetfinder": tool_results["assetfinder"]["parsed_output"],
                "findomain": tool_results["findomain"]["parsed_output"],
                "gau": tool_results["gau"]["parsed_output"],
                "naabu": tool_results["naabu"]["parsed_output"],
                "httpx": tool_results["httpx"]["parsed_output"],
                "nmap": tool_results["nmap"]["parsed_output"],
                "nuclei": tool_results["nuclei"]["parsed_output"],
                "waybackurls": tool_results["waybackurls"]["parsed_output"],
                "wappalyzer": tool_results["wappalyzer"]["parsed_output"],
                "whatweb": tool_results["whatweb"]["parsed_output"],
                "wapiti": tool_results["wapiti"]["parsed_output"],
                "dirsearch": tool_results["dirsearch"]["parsed_output"],
            }
        )


class DNSQueryView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def post(self, request):
        domain = normalize_target(request.data.get("domain"))

        if not domain:
            return Response({"error": "domain is required"}, status=400)

        return Response(query_dns(domain))


class EmailSecurityView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def post(self, request):
        domain = normalize_target(request.data.get("domain"))

        if not domain:
            return Response({"error": "domain is required"}, status=400)

        return Response(run_email_security_scan(domain))


class ReconScanListView(ListAPIView):
    serializer_class = ReconScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        queryset = ReconScan.objects.filter(org_id=org_id).order_by("-created_at")
        target = normalize_target(self.request.query_params.get("target"))

        if target:
            queryset = queryset.filter(target=target)

        return queryset


class ToolOutputListView(ListAPIView):
    serializer_class = ToolOutputSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        queryset = ToolOutput.objects.filter(scan__org_id=org_id).order_by("-created_at")
        scan_id = self.request.query_params.get("scan_id")

        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)

        return queryset


class DiscoveredDomainListView(ListAPIView):
    serializer_class = DiscoveredDomainSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "subdomains"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        queryset = DiscoveredDomain.objects.filter(org_id=org_id).order_by("-created_at")
        scan_id = self.request.query_params.get("scan_id")

        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)

        return queryset[:100]


class ReconEndpointListView(ListAPIView):
    serializer_class = ReconEndpointSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "endpoints"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        queryset = ReconEndpoint.objects.filter(org_id=org_id).order_by("-created_at")
        scan_id = self.request.query_params.get("scan_id")

        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)

        return queryset[:100]


class APIInspectView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def post(self, request):
        target = normalize_target(request.data.get("target"))
        if not target:
            return Response({"error": "target is required"}, status=400)
        return Response(detect_api_technology(target))


class MethodScanView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def post(self, request):
        target = request.data.get("target")
        if not target:
            return Response({"error": "target is required"}, status=400)

        url = target if target.startswith("http") else f"https://{target}"
        return Response(test_http_methods(url))


class CollectApiUrlsView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "reconnaissance"

    def post(self, request):
        target = normalize_target(request.data.get("target"))
        if not target:
            return Response({"error": "target is required"}, status=400)
        return Response(collect_api_urls(target))


def get_future_result(name, future, target):
    try:
        return future.result()
    except Exception as exc:
        if name == "email_security":
            return {
                "domain": target,
                "error": f"Email security scan failed: {exc}",
                "root_txt": [],
                "spf": [],
                "dmarc": [],
                "mx": [],
                "dkim_selector1": [],
                "dkim_default": [],
                "smtp_hosts": [],
                "smtp_port_scan": {"total_hosts": 0, "total_ports": 0, "hosts": [], "ports": []},
                "smtp_open_relay": {"total_hosts": 0, "total_ports": 0, "hosts": [], "ports": []},
                "smtp_starttls": {},
            }

        if name in {"subfinder", "assetfinder", "findomain"}:
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_subdomains": 0,
                    "subdomains": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "gau":
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_endpoints": 0,
                    "endpoints": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "naabu":
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_open_ports": 0,
                    "open_ports": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "httpx":
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_live_hosts": 0,
                    "live_hosts": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "nmap":
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_hosts": 0,
                    "total_ports": 0,
                    "hosts": [],
                    "ports": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "nuclei":
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_vulnerabilities": 0,
                    "vulnerabilities": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name in ("waybackurls",):
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_urls": 0,
                    "urls": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name in ("wappalyzer", "whatweb"):
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_detected": 0,
                    "hosts": [],
                    "technologies_summary": {},
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "wapiti":
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_vulnerabilities": 0,
                    "vulnerabilities": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "dirsearch":
            return {
                "raw_output": "",
                "parsed_output": {
                    "total_directories": 0,
                    "directories": [],
                    "error": f"{name} failed: {exc}",
                },
            }

        if name == "dig":
            return {
                "domain": target,
                "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [],
                "error": f"dig/DNS query failed: {exc}",
            }

        return {
            "raw_output": "",
            "parsed_output": {
                "error": f"{name} failed: {exc}",
            },
        }


def collect_subdomains(*results):
    subdomains = []

    for result in results:
        for item in result["parsed_output"].get("subdomains", []):
            subdomain = item.get("subdomain")

            if subdomain:
                subdomains.append(subdomain)

    return dedupe_preserve_order(subdomains)


def persist_tool_outputs(scan, tool_results):
    for tool_name, result in tool_results.items():
        ToolOutput.objects.create(
            scan=scan,
            tool_name=tool_name,
            raw_output=result.get("raw_output", ""),
            parsed_output=result["parsed_output"],
        )


def persist_domains(scan, target, tool_results):
    discovery_sources = ("subfinder", "assetfinder", "findomain")
    new_domains = []

    for source in discovery_sources:
        for item in tool_results[source]["parsed_output"].get("subdomains", []):
            subdomain = item.get("subdomain")
            if not subdomain:
                continue
            _, created = DiscoveredDomain.objects.get_or_create(
                scan=scan,
                subdomain=subdomain,
                defaults={"org_id": scan.org_id, "root_domain": target, "source": source},
            )
            if created:
                new_domains.append(subdomain)

    return new_domains


def persist_endpoints(scan, tool_results):
    for item in tool_results["httpx"]["parsed_output"].get("live_hosts", []):
        url = item.get("url")
        if not url:
            continue
        ReconEndpoint.objects.get_or_create(
            scan=scan,
            url=url,
            defaults={
                "org_id": scan.org_id, "source": "httpx", "method": "GET",
                "status_code": item.get("status_code"),
                "has_params": ("?" in url),
            },
        )

    for item in tool_results["gau"]["parsed_output"].get("endpoints", []):
        url = item.get("url")
        if not url:
            continue
        ReconEndpoint.objects.get_or_create(
            scan=scan,
            url=url,
            defaults={
                "org_id": scan.org_id, "source": "gau", "method": "GET",
                "has_params": ("?" in url),
            },
        )

    for item in tool_results["nuclei"]["parsed_output"].get("vulnerabilities", []):
        url = item.get("target")
        if not url or not url.startswith("http"):
            continue
        ReconEndpoint.objects.get_or_create(
            scan=scan,
            url=url,
            defaults={
                "org_id": scan.org_id, "source": "nuclei", "method": "GET",
                "has_params": ("?" in url),
            },
        )
