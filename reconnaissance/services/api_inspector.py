import json
import re
import requests
from urllib.parse import urlparse
from .command_utils import (
    add_execution_error,
    dedupe_preserve_order,
    extract_hostnames,
    normalize_target,
    run_command,
    resolve_executable,
)


SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger-ui", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/api/swagger.json",
]


def detect_api_technology(target):
    parsed = urlparse(target if "://" in target else f"https://{target}")
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc

    result = {
        "domain": domain,
        "base_url": base_url,
        "url_patterns": {},
        "headers": {},
        "options": {},
        "swagger_paths": [],
        "detected_techs": [],
    }

    detect_from_url_pattern(base_url, result)
    inspect_headers(base_url, result)
    check_options(base_url, result)
    find_swagger_files(base_url, result)

    techs = set()
    if result["swagger_paths"]:
        techs.add("Swagger/OpenAPI")
    if result["url_patterns"].get("graphql"):
        techs.add("GraphQL")
    if result["url_patterns"].get("soap"):
        techs.add("SOAP")
    if result["options"].get("allow"):
        techs.add("REST")
    if result["headers"].get("content_type") == "application/grpc":
        techs.add("gRPC")
    if not techs:
        techs.add("REST")

    result["detected_techs"] = sorted(techs)
    return result


def detect_from_url_pattern(base_url, result):
    patterns = {
        "graphql": ["/graphql", "/graphiql", "/playground", "/graphql/console"],
        "rest": ["/api", "/v1/", "/v2/", "/v3/", "/rest"],
        "soap": ["/wsdl", "/soap", "/service"],
        "grpc": [], # detected via headers
    }

    hit_patterns = {}
    for tech, paths in patterns.items():
        found = []
        for path in paths:
            try:
                resp = requests.get(f"{base_url}{path}", timeout=10, verify=False)
                if resp.status_code in (200, 401, 403, 405):
                    found.append({"path": path, "status": resp.status_code})
            except requests.RequestException:
                pass
        if found:
            hit_patterns[tech] = found

    result["url_patterns"] = hit_patterns


def inspect_headers(base_url, result):
    try:
        resp = requests.get(base_url, timeout=10, verify=False)
        headers = {
            "content_type": resp.headers.get("Content-Type", ""),
            "server": resp.headers.get("Server", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
            "via": resp.headers.get("Via", ""),
        }
        if resp.headers.get("grpc-status") is not None:
            headers["grpc_status"] = resp.headers["grpc-status"]
            headers["content_type"] = "application/grpc"
        result["headers"] = {k: v for k, v in headers.items() if v}
    except requests.RequestException:
        pass


def check_options(base_url, result):
    paths_to_check = ["/api", "/", "/v1", "/v2"]
    for path in paths_to_check:
        try:
            resp = requests.options(f"{base_url}{path}", timeout=10, verify=False)
            allow = resp.headers.get("Allow", "")
            if allow:
                result["options"] = {
                    "path": path,
                    "allow": [m.strip() for m in allow.split(",")],
                    "status": resp.status_code,
                }
                break
        except requests.RequestException:
            pass


def find_swagger_files(base_url, result):
    for path in SWAGGER_PATHS:
        try:
            resp = requests.get(f"{base_url}{path}", timeout=10, verify=False)
            if resp.status_code == 200:
                spec = {}
                try:
                    spec = resp.json()
                except (json.JSONDecodeError, ValueError):
                    spec = {"found": True}
                result["swagger_paths"].append({
                    "path": path,
                    "endpoint_count": len(spec.get("paths", {})) if isinstance(spec, dict) else 0,
                })
        except requests.RequestException:
            pass


def test_http_methods(target_url):
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    results = []

    for method in methods:
        try:
            resp = requests.request(method, target_url, timeout=15, verify=False)
            results.append({
                "method": method,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
            })
        except requests.RequestException as e:
            results.append({
                "method": method,
                "status_code": None,
                "error": str(e),
            })

    return {
        "url": target_url,
        "results": results,
        "allowed_methods": [r["method"] for r in results if r["status_code"] and r["status_code"] not in (404, 405)],
    }


def collect_api_urls(domain):
    raw_urls = set()
    gau_path = resolve_executable("gau", env_var="GAU_PATH")
    wayback_path = resolve_executable("waybackurls", env_var="WAYBACKURLS_PATH")

    if gau_path:
        result = run_command([gau_path, domain], timeout=120)
        if result["stdout"]:
            for line in result["stdout"].splitlines():
                url = line.strip()
                if url:
                    raw_urls.add(url)

    if wayback_path:
        result = run_command([wayback_path, domain], timeout=120)
        if result["stdout"]:
            for line in result["stdout"].splitlines():
                url = line.strip()
                if url:
                    raw_urls.add(url)

    api_pattern = re.compile(r"(api|v1|v2|v3|graphql|swagger|rest)", re.IGNORECASE)
    filtered = [u for u in raw_urls if api_pattern.search(u)]

    return {
        "domain": domain,
        "total_urls": len(raw_urls),
        "api_urls": sorted(filtered),
        "total_api_urls": len(filtered),
    }
