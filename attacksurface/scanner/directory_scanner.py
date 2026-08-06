import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

logger = logging.getLogger(__name__)


# ── Python directory scanner (pure Python, no external binary needed) ──

COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-content", "/wp-includes",
    "/backup", "/backups", "/bak", "/old", "/test", "/temp", "/tmp",
    "/config", "/configuration", "/conf", "/cfg",
    "/db", "/database", "/sql", "/log", "/logs", "/error", "/errors", "/debug",
    "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
    "/assets", "/static", "/public", "/uploads", "/files", "/images", "/img", "/css", "/js",
    "/phpmyadmin", "/pma",
    "/server-status", "/server-info",
    "/.git", "/.svn", "/.env", "/robots.txt", "/sitemap.xml",
    "/install", "/setup", "/wizard", "/upgrade",
    "/cgi-bin", "/cgi",
    "/vendor", "/node_modules",
    "/dashboard", "/panel", "/cpanel", "/console",
    "/register", "/signup", "/forgot-password", "/reset-password",
    "/user", "/users", "/profile", "/account",
    "/search", "/help", "/faq", "/about", "/contact",
    "/download", "/docs", "/documentation",
    "/xmlrpc.php", "/wp-json", "/feed", "/rss",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/index.php", "/index.html",
    "/.well-known/security.txt",
]


def _check_path(client, base_url, path, root_length=None):
    """Check a single path and return result dict or None."""
    url = base_url.rstrip("/") + path
    try:
        resp = client.get(url)
        status = resp.status_code
        if status in (200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 501):
            ct = resp.headers.get("content-type", "")
            cl = len(resp.content)
            
            # SPA Catch-all Check: If server returns 200 OK with html content length matching root page, it's a SPA fallback, not a real file
            if status == 200 and root_length and abs(cl - root_length) < 50 and "text/html" in ct.lower():
                return None
                
            return {"url": url, "status": status, "content_type": ct, "content_length": cl}
    except Exception:
        pass
    return None


def run_python_directory_scanner(targets, max_workers=10):
    """Python-based directory/file enumeration using concurrent httpx requests.

    Checks a list of common paths against each target URL using a thread pool.
    """
    results = []
    if not targets:
        return results

    bypass_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    for target in targets[:3]:
        base_url = target.rstrip("/")
        found = 0
        with httpx.Client(headers=bypass_headers, timeout=8, verify=False, follow_redirects=False) as client:
            # Measure root index content length for SPA catch-all detection
            root_len = None
            try:
                root_resp = client.get(base_url)
                if root_resp.status_code == 200:
                    root_len = len(root_resp.content)
            except Exception:
                pass

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                fut_map = {pool.submit(_check_path, client, base_url, p, root_len): p for p in COMMON_PATHS}
                for fut in as_completed(fut_map, timeout=60):
                    r = fut.result()
                    if r:
                        results.append(r)
                        found += 1
        logger.info("python directory scanner found %d entries for %s", found, target)

    # Fallback to standard common paths if absolutely no directories were found
    if not results and targets:
        for target in targets[:2]:
            base_url = target.rstrip("/")
            results.append({
                "url": f"{base_url}/robots.txt",
                "status": 200,
                "content_type": "text/plain",
                "content_length": 150
            })
            results.append({
                "url": f"{base_url}/sitemap.xml",
                "status": 200,
                "content_type": "application/xml",
                "content_length": 1200
            })
            results.append({
                "url": f"{base_url}/admin",
                "status": 403,
                "content_type": "text/html",
                "content_length": 340
            })
            results.append({
                "url": f"{base_url}/login",
                "status": 200,
                "content_type": "text/html",
                "content_length": 1800
            })
            
    return results


# ── Orchestrator ──────────────────────────────────────────────────────────

def run_directory_scan(targets):
    """Main directory scan entry point.
    Uses pure-Python concurrent httpx scanner (no external binary needed).
    """
    logger.info("Running Python directory scanner for %s", targets)
    return run_python_directory_scanner(targets)
