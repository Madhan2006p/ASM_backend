import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urljoin

import httpx

from .command_utils import (
    combine_output,
    resolve_executable,
    run_command,
)

logger = logging.getLogger(__name__)

DIRSEARCH_CANDIDATES = (
    r"C:\Python310\Scripts\dirsearch.exe",
    r"C:\Python311\Scripts\dirsearch.exe",
    r"C:\Python312\Scripts\dirsearch.exe",
    r"C:\Users\samyu\AppData\Local\Programs\Python\Python312\Scripts\dirsearch.exe",
)

# Cap the body we read for content inspection.
MAX_BODY_BYTES = 256 * 1024

# Statuses worth keeping. 404 responses are not "discoveries".
STATUS_OF_INTEREST = {
    200, 201, 202, 204, 206,
    301, 302, 303, 307, 308,
    401, 403, 405, 406, 407, 410,
    500, 501, 502, 503, 504,
}

# Common directory paths for Python fallback scanner
COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-content", "/wp-includes",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
    "/.svn/entries", "/.hg/store", "/.htaccess", "/.htpasswd",
    "/config", "/config.yml", "/config.yaml", "/config.json", "/config.inc.php",
    "/configuration.php", "/wp-config.php", "/settings.py", "/appsettings.json",
    "/web.config", "/php.ini", "/phpinfo.php", "/info.php",
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.bak",
    "/db.sql", "/database.sql", "/dump.sql", "/data.sql", "/site.zip",
    "/phpmyadmin", "/phpmyadmin/", "/adminer.php", "/adminer",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt", "/server-status", "/console",
    "/debug", "/test", "/shell", "/cmd", "/upload", "/uploads",
    "/assets", "/static", "/js", "/css", "/images", "/img",
    "/download", "/downloads", "/docs", "/documentation",
    "/cgi-bin", "/cgi-bin/test.cgi", "/cpanel", "/webmail",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/requirements.txt", "/.npmrc", "/.env.example", "/.gitignore",
    "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/index.php", "/index.html", "/index.js", "/index.jsp",
    "/default.aspx", "/default.jsp", "/default.php",
    "/error", "/errors", "/error.log", "/access.log",
    "/application.log", "/debug.log", "/apache-access.log", "/nginx-access.log",
    "/monitoring", "/status", "/health", "/healthcheck",
    "/metrics", "/prometheus", "/actuator", "/actuator/env",
    "/actuator/health", "/actuator/heapdump", "/actuator/mappings",
    "/.aws/credentials", "/.aws/config",
    "/.azure/credentials", "/.gcp/credentials",
    "/.npm/_cacache", "/.yarn", "/.yarnrc.yml",
    "/bower_components", "/node_modules", "/vendor",
    "/tmp", "/temp", "/logs", "/log", "/cache",
    "/old", "/new", "/.bak", "/.old", "/.orig",
    "/private", "/secret", "/conf", "/configuration",
    "/sw.js", "/manifest.json", "/service-worker.js",
    "/rss", "/feed", "/atom.xml", "/news.xml",
    "/ws", "/wss", "/socket.io", "/api/ws",
    "/oauth", "/oauth2", "/oauth2/token",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/callback", "/redirect", "/login/callback",
    "/signin", "/signout", "/logout", "/register",
    "/forgot-password", "/reset-password",
    "/profile", "/settings", "/account",
    "/users", "/user", "/search", "/explore",
    "/api/graphql", "/api/rest", "/api/soap",
    "/api-docs", "/api-explorer", "/openapi.json",
    "/swagger.json", "/swagger-ui", "/redoc",
    "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/beans",
]

ALL_PATHS = list(dict.fromkeys(COMMON_PATHS))


def run_dirsearch(targets):
    """Run dirsearch for directory enumeration on targets."""
    if isinstance(targets, str):
        targets = [targets]

    executable = resolve_executable(
        "dirsearch",
        env_var="DIRSEARCH_PATH",
        candidates=DIRSEARCH_CANDIDATES,
    )

    if executable:
        return _run_dirsearch_binary(executable, targets)
    else:
        logger.info("dirsearch binary not found, using Python fallback")
        return _run_python_dirsearch(targets)


def _run_dirsearch_binary(executable, targets):
    """Run dirsearch binary and parse JSON output.

    The binary provides no response bodies, so entries are classified with
    path + status heuristics (analyze_entry) rather than full content analysis.
    """
    from attacksurface.scanner.directory_analyzer import analyze_entry

    all_results = []
    all_raw = []

    for target in targets[:3]:
        target_url = target if (target.startswith("http://") or target.startswith("https://")) else f"https://{target}"

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmpf:
            tmp_path = tmpf.name

        try:
            args = [
                executable, "-u", target_url, "-o", tmp_path, "-f",
                "--format", "json", "-q", "--timeout", "5", "--max-time", "60",
            ]
            execution = run_command(args, timeout=90)
            all_raw.append(combine_output(execution["stdout"], execution["stderr"]))

            if Path(tmp_path).exists():
                content = Path(tmp_path).read_text(encoding="utf-8", errors="ignore").strip()
                if content:
                    data = json.loads(content)
                    entries = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    for entry in entries:
                        url = entry.get("url", "")
                        status = entry.get("status", 0)
                        if isinstance(status, str):
                            try:
                                status = int(status)
                            except (ValueError, TypeError):
                                status = 0
                        content_type = entry.get("content-type", "") or entry.get("content_type", "")
                        content_length = entry.get("content-length", 0) or entry.get("content_length", 0) or entry.get("length", 0)
                        analysis = analyze_entry(url, status, content_type, content_length)
                        all_results.append({
                            "url": url,
                            "status": status,
                            "content_type": content_type,
                            "content_length": content_length,
                            "category": analysis["category"],
                            "risk": analysis["risk"],
                            "access_status": analysis["access_status"],
                            "is_sensitive": analysis["is_sensitive"],
                            "sensitive_matches": analysis["sensitive_matches"],
                        })
        except Exception as e:
            logger.warning("dirsearch failed for %s: %s", target, e)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    parsed_output = {
        "total_directories": len(all_results),
        "directories": all_results,
        "targets_scanned": targets[:3],
    }

    return {
        "raw_output": "\n---\n".join(all_raw) if all_raw else "",
        "parsed_output": parsed_output,
    }


REDIRECT_STATUSES = (301, 302, 303, 307, 308)
MAX_REDIRECT_HOPS = 5


def _fetch(client, url, max_bytes=MAX_BODY_BYTES, max_hops=MAX_REDIRECT_HOPS):
    """Streamed GET with a body cap; return (status, headers, body).

    Redirects are followed (bounded) so the recorded status is the final one
    a browser would see (e.g. /assets -> 301 -> /assets/ -> 403).
    """
    current = url
    hops = 0
    while hops <= max_hops:
        try:
            with client.stream("GET", current, follow_redirects=False) as resp:
                status = resp.status_code
                headers = dict(resp.headers)
                location = headers.get("location")
                if status in REDIRECT_STATUSES and location:
                    current = urljoin(current, location)
                    hops += 1
                    continue
                chunks = []
                total = 0
                for chunk in resp.iter_bytes():
                    if not chunk:
                        continue
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= max_bytes:
                        break
                return status, headers, b"".join(chunks)
        except Exception:
            break
    return None, {}, b""


def _run_python_dirsearch(targets):
    """Python-based directory scanner fallback using httpx.

    Captures response bodies, compares against the site baseline (soft-404
    detection) and classifies each entry with the shared content analyzer.
    """
    from attacksurface.scanner.directory_analyzer import analyze_response, normalized_body_hash

    all_results = []

    for target in targets[:3]:
        base_url = target if (target.startswith("http://") or target.startswith("https://")) else f"https://{target}"
        base_url = base_url.rstrip("/")

        bypass_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            with httpx.Client(
                headers=bypass_headers,
                timeout=10,
                verify=False,
                follow_redirects=False,
            ) as client:
                from concurrent.futures import ThreadPoolExecutor, as_completed

                # Baseline for soft-404 detection (follows redirects, matching
                # how candidate paths are probed)
                baseline_hash = None
                base_status, _base_headers, base_body = _fetch(client, base_url)
                if base_status is not None and base_status < 500:
                    baseline_hash = normalized_body_hash(base_body)

                def _check_path(path):
                    url = f"{base_url}{path}"
                    status, headers, body = _fetch(client, url)
                    if status is None or status not in STATUS_OF_INTEREST:
                        return None
                    content_length = len(body)
                    try:
                        header_length = int(headers.get("content-length", 0) or 0)
                        if header_length > 0:
                            content_length = header_length
                    except (ValueError, TypeError):
                        pass
                    analysis = analyze_response(
                        url, status, headers, body,
                        baseline_hash=baseline_hash,
                        content_length=content_length,
                    )
                    if not analysis["found"]:
                        return None
                    return {
                        "url": url,
                        "status": status,
                        "content_type": analysis["content_type"],
                        "content_length": analysis["content_length"],
                        "category": analysis["category"],
                        "risk": analysis["risk"],
                        "access_status": analysis["access_status"],
                        "is_sensitive": analysis["is_sensitive"],
                        "sensitive_matches": analysis["sensitive_matches"],
                        "title": analysis["title"],
                        "preview": analysis["preview"],
                    }

                with ThreadPoolExecutor(max_workers=10) as pool:
                    fut_map = {pool.submit(_check_path, p): p for p in ALL_PATHS}
                    try:
                        for fut in as_completed(fut_map, timeout=120):
                            r = fut.result()
                            if r:
                                all_results.append(r)
                    except TimeoutError:
                        # Keep whatever completed before the deadline
                        for fut in fut_map:
                            if fut.done() and not fut.cancelled():
                                try:
                                    r = fut.result()
                                    if r:
                                        all_results.append(r)
                                except Exception:
                                    pass
        except Exception as e:
            logger.warning("Python dirsearch failed for %s: %s", target, e)

    parsed_output = {
        "total_directories": len(all_results),
        "directories": all_results,
        "targets_scanned": targets[:3],
        "note": "Used Python fallback scanner (dirsearch binary not available)",
    }

    return {
        "raw_output": "",
        "parsed_output": parsed_output,
    }
