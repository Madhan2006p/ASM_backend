from celery import shared_task
from concurrent.futures import ThreadPoolExecutor

from .models import ReconScan, ToolOutput, DiscoveredDomain, ReconEndpoint
from .services.api_inspector import detect_api_technology, test_http_methods, collect_api_urls
from .services.assetfinder_scanner import run_assetfinder
from .services.dirsearch_scanner import run_dirsearch
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
from .services.email_security_scanner import run_email_security_scan


@shared_task(bind=True)
def run_scheduled_recon_scan(self, target="kongu.ac.in"):
    scan = ReconScan.objects.create(target=target, status="running", progress=0, org_id=None)

    executor = ThreadPoolExecutor(max_workers=10)

    futures = {
        "subfinder": executor.submit(run_subfinder, target),
        "assetfinder": executor.submit(run_assetfinder, target),
        "findomain": executor.submit(run_findomain, target),
        "gau": executor.submit(run_gau, target),
        "naabu": executor.submit(run_naabu, target),
        "nmap": executor.submit(run_nmap, target),
        "nuclei": executor.submit(run_nuclei, target),
        "waybackurls": executor.submit(run_waybackurls, target),
        "wappalyzer": executor.submit(run_wappalyzer, target),
        "whatweb": executor.submit(run_whatweb_scan, target),
        "email_security": executor.submit(run_email_security_scan, target),
    }

    results = {}
    for name, future in futures.items():
        try:
            results[name] = future.result()
        except Exception as exc:
            results[name] = {"raw_output": "", "parsed_output": {"error": f"{name} failed: {exc}"}}

    executor.shutdown(wait=True)

    # Run httpx on the collected subdomains
    combined_subdomains = []
    for src in ("subfinder", "assetfinder", "findomain"):
        if src in results:
            for item in results[src]["parsed_output"].get("subdomains", []):
                sd = item.get("subdomain")
                if sd:
                    combined_subdomains.append(sd)
    httpx_inputs = combined_subdomains or [target]
    try:
        httpx_result = run_httpx(httpx_inputs)
    except Exception:
        httpx_result = {"raw_output": "", "parsed_output": {"total_live_hosts": 0, "live_hosts": []}}
    results["httpx"] = httpx_result

    # Run dirsearch and wapiti on live URLs
    live_urls = [item["url"] for item in httpx_result["parsed_output"].get("live_hosts", []) if item.get("url")]
    if live_urls:
        try:
            results["dirsearch"] = run_dirsearch(live_urls)
        except Exception:
            results["dirsearch"] = {"raw_output": "", "parsed_output": {"total_directories": 0, "directories": []}}
        try:
            results["wapiti"] = run_wapiti(live_urls)
        except Exception:
            results["wapiti"] = {"raw_output": "", "parsed_output": {"total_vulnerabilities": 0, "vulnerabilities": []}}

    # Save tool outputs
    # Wrap email_security result into standard format
    if "email_security" in results and isinstance(results["email_security"], dict) and "raw_output" not in results["email_security"]:
        results["email_security"] = {
            "raw_output": "",
            "parsed_output": results["email_security"],
        }

    for tool_name, result in results.items():
        ToolOutput.objects.create(
            scan=scan, tool_name=tool_name,
            raw_output=result.get("raw_output", ""),
            parsed_output=result["parsed_output"],
        )

    # Save discovered domains
    for src in ("subfinder", "assetfinder", "findomain"):
        if src in results:
            for item in results[src]["parsed_output"].get("subdomains", []):
                sd = item.get("subdomain")
                if sd:
                    DiscoveredDomain.objects.get_or_create(
                        scan=scan,
                        subdomain=sd,
                        defaults={"root_domain": target, "source": f"scheduled-{src}"},
                    )

    # Save endpoints
    if "httpx" in results:
        for item in results["httpx"]["parsed_output"].get("live_hosts", []):
            url = item.get("url")
            if url:
                ReconEndpoint.objects.get_or_create(
                    scan=scan, url=url,
                    defaults={"source": "scheduled-httpx", "method": "GET", "has_params": ("?" in url)},
                )

    if "gau" in results:
        for item in results["gau"]["parsed_output"].get("endpoints", []):
            url = item.get("url")
            if url:
                ReconEndpoint.objects.get_or_create(
                    scan=scan, url=url,
                    defaults={"source": "scheduled-gau", "method": "GET", "has_params": ("?" in url)},
                )

    if "nuclei" in results:
        for item in results["nuclei"]["parsed_output"].get("vulnerabilities", []):
            url = item.get("target")
            if url and url.startswith("http"):
                ReconEndpoint.objects.get_or_create(
                    scan=scan, url=url,
                    defaults={"source": "scheduled-nuclei", "method": "GET", "has_params": ("?" in url)},
                )

    scan.progress = 100
    scan.status = "completed"
    scan.save()

    return {"target": target, "status": "completed", "scan_id": scan.id}


@shared_task(bind=True)
def run_api_inspection(self, scan_id):
    scan = ReconScan.objects.get(id=scan_id)
    scan.status = "running"
    scan.progress = 10
    scan.save()

    result = detect_api_technology(scan.target)

    ToolOutput.objects.create(
        scan=scan, tool_name="api_inspector",
        raw_output="", parsed_output=result,
    )

    scan.progress = 100
    scan.status = "completed"
    scan.save()
    return result


@shared_task(bind=True)
def run_method_scan(self, scan_id):
    scan = ReconScan.objects.get(id=scan_id)
    scan.status = "running"
    scan.progress = 10
    scan.save()

    targets = [scan.target]
    tool_outputs = ToolOutput.objects.filter(scan=scan, tool_name="api_inspector")
    if tool_outputs.exists():
        data = tool_outputs.first().parsed_output
        if data.get("swagger_paths"):
            base = data["base_url"]
            for sp in data["swagger_paths"]:
                targets.append(f"{base}{sp['path']}")

    all_results = []
    for i, t in enumerate(targets):
        result = test_http_methods(t)
        all_results.append(result)
        scan.progress = 10 + int((i + 1) / len(targets) * 80)
        scan.save(update_fields=["progress"])

    ToolOutput.objects.create(
        scan=scan, tool_name="method_scanner",
        raw_output="", parsed_output={"targets": all_results},
    )

    scan.progress = 100
    scan.status = "completed"
    scan.save()
    return {"target": scan.target, "targets_scanned": len(targets)}


@shared_task(bind=True)
def run_api_url_collection(self, scan_id):
    scan = ReconScan.objects.get(id=scan_id)
    scan.status = "running"
    scan.progress = 10
    scan.save()

    result = collect_api_urls(scan.target)

    ToolOutput.objects.create(
        scan=scan, tool_name="api_url_collector",
        raw_output="", parsed_output=result,
    )

    scan.progress = 100
    scan.status = "completed"
    scan.save()
    return result
