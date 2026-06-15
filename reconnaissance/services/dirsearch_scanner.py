import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .command_utils import (
    add_execution_error,
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

# Common directory paths for Python fallback scanner
COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-content", "/wp-includes",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
    "/.env", "/.git/config", "/.git/HEAD", "/config", "/backup",
    "/phpmyadmin", "/phpinfo.php", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/.htaccess", "/aws/credentials",
    "/.well-known/security.txt", "/server-status", "/console",
    "/debug", "/test", "/shell", "/cmd", "/upload", "/uploads",
    "/assets", "/static", "/js", "/css", "/images", "/img",
    "/download", "/downloads", "/docs", "/documentation",
    "/cgi-bin", "/cgi-bin/test.cgi", "/cpanel", "/webmail",
    "/.svn/entries", "/Dockerfile", "/docker-compose.yml",
    "/package.json", "/package-lock.json", "/requirements.txt",
    "/.npmrc", "/.env.example", "/.gitignore", "/.dockerignore",
    "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/index.php", "/index.html", "/index.js", "/index.jsp",
    "/default.aspx", "/default.jsp", "/default.php",
    "/error", "/errors", "/error.log", "/access.log",
    "/monitoring", "/status", "/health", "/healthcheck",
    "/metrics", "/prometheus", "/actuator",
    "/.aws/credentials", "/.aws/config",
    "/.azure/credentials", "/.gcp/credentials",
    "/.npm/_cacache", "/.yarn", "/.yarnrc.yml",
    "/bower_components", "/node_modules", "/vendor",
    "/tmp", "/temp", "/logs", "/log", "/cache",
    "/old", "/new", "/backup", "/bak", "/.bak",
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
    """Run dirsearch binary and parse JSON output."""
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
                        all_results.append({
                            "url": url,
                            "status": status,
                            "content_type": content_type,
                            "content_length": content_length,
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


def _run_python_dirsearch(targets):
    """Python-based directory scanner fallback using httpx."""
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
                timeout=8,
                verify=False,
                follow_redirects=False,
            ) as client:
                from concurrent.futures import ThreadPoolExecutor, as_completed

                def _check_path(path):
                    url = f"{base_url}{path}"
                    try:
                        resp = client.get(url)
                        if resp.status_code and resp.status_code not in (404,):
                            return {
                                "url": url,
                                "status": resp.status_code,
                                "content_type": resp.headers.get("content-type", ""),
                                "content_length": len(resp.content),
                            }
                    except Exception:
                        pass
                    return None

                with ThreadPoolExecutor(max_workers=10) as pool:
                    fut_map = {pool.submit(_check_path, p): p for p in COMMON_PATHS}
                    for fut in as_completed(fut_map, timeout=60):
                        r = fut.result()
                        if r:
                            all_results.append(r)
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
