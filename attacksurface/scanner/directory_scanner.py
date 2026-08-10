import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import httpx

from .directory_analyzer import analyze_response, normalized_body_hash

logger = logging.getLogger(__name__)

# Cap how much of each response body we read — enough for content inspection,
# cheap enough to keep the scan fast.
MAX_BODY_BYTES = 256 * 1024

# Statuses worth recording. 404 is deliberately excluded: non-existent paths
# are the common case for a wordlist and would flood the results.
STATUS_OF_INTEREST = {
    200, 201, 202, 204, 206,
    301, 302, 303, 307, 308,
    401, 403, 405, 406, 407, 410,
    500, 501, 502, 503, 504,
}

# ── Path wordlists ──────────────────────────────────────────────────────────

COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-content", "/wp-includes",
    "/backup", "/backups", "/bak", "/old", "/test", "/temp", "/tmp",
    "/config", "/configuration", "/conf", "/cfg",
    "/db", "/database", "/sql", "/log", "/logs", "/error", "/errors", "/debug",
    "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
    "/assets", "/static", "/public", "/uploads", "/files", "/images", "/img",
    "/css", "/js",
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
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/actuator/mappings", "/actuator/beans", "/metrics", "/prometheus",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/api-docs", "/v2/api-docs", "/v3/api-docs", "/graphiql",
]

# High-value sensitive files (path-based probes).
SENSITIVE_FILE_PATHS = [
    # Environment / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.example", "/.env.backup", "/.env.old", "/.env.save",
    "/.aws/credentials", "/.aws/config",
    "/.azure/credentials", "/.gcp/credentials",
    "/.htaccess", "/.htpasswd",
    "/.npmrc", "/.pypirc", "/.gitconfig", "/.ssh/id_rsa", "/.ssh/id_rsa.pub",
    "/.bashrc", "/.bash_history", "/.profile", "/.zshrc",
    # VCS metadata
    "/.git/config", "/.git/HEAD", "/.git/index", "/.git/refs/heads/main",
    "/.git/refs/heads/master", "/.svn/entries", "/.hg/store",
    # Backups / archives / dumps
    "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.sql", "/backup.bak",
    "/backups.zip", "/db.sql", "/database.sql", "/dump.sql", "/data.sql",
    "/dump.tar.gz", "/site.zip", "/www.zip", "/web.zip", "/public_html.zip",
    "/old.zip", "/data.zip", "/wwwroot.zip", "/html.zip", "/backup.7z",
    # Config files
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
    "/config.php", "/config.php.bak", "/config.php.old", "/configuration.php",
    "/config.yml", "/config.yaml", "/config.json", "/config.inc.php",
    "/conn.php", "/db.php", "/database.php", "/settings.py", "/settings.json",
    "/application.properties", "/application.yml", "/application.yaml",
    "/appsettings.json", "/appsettings.Development.json", "/web.config",
    "/php.ini", "/phpinfo.php", "/info.php", "/test.php",
    # Project manifests
    "/docker-compose.yml", "/docker-compose.yaml", "/docker-compose.override.yml",
    "/Dockerfile", "/package.json", "/package-lock.json", "/yarn.lock",
    "/requirements.txt", "/Pipfile", "/poetry.lock", "/composer.json",
    "/composer.lock", "/Gemfile", "/Gemfile.lock", "/pom.xml",
    "/build.gradle", "/settings.gradle", "/gradle.properties",
    "/README.md", "/CHANGELOG.md", "/LICENSE",
    # Logs
    "/access.log", "/error.log", "/debug.log", "/application.log",
    "/apache-access.log", "/apache-error.log", "/nginx-access.log",
    "/nginx-error.log", "/auth.log", "/syslog", "/secure",
    # Debug / metadata endpoints
    "/server-status", "/server-info", "/status", "/health", "/debug", "/trace",
    # Admin tooling
    "/phpmyadmin/", "/phpmyadmin/index.php", "/adminer.php", "/adminer",
    "/cpanel/", "/webmail/", "/manager/html",
    # Docs / API surface
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/manifest.json", "/humans.txt",
    "/graphql", "/graphiql", "/api/graphql", "/api/v1/users", "/api/v1/config",
    "/api/v1/status", "/api/v1/health", "/api/v1/env", "/api/v1/debug",
    "/api/health", "/api/status", "/api/config",
    # Generic interesting paths
    "/uploads/", "/files/", "/downloads/", "/private/", "/secret/",
    "/internal/", "/temp/", "/cache/", "/shell", "/cmd",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

ALL_PATHS = list(dict.fromkeys(COMMON_PATHS + SENSITIVE_FILE_PATHS))


REDIRECT_STATUSES = (301, 302, 303, 307, 308)
MAX_REDIRECT_HOPS = 5


def _fetch(client, url, max_bytes=MAX_BODY_BYTES, max_hops=MAX_REDIRECT_HOPS):
    """GET with streaming; return (status, headers, body) with body capped.

    Redirects are followed (bounded to ``max_hops``) so the recorded status is
    the one a browser actually sees — e.g. ``/assets`` -> 301 -> ``/assets/``
    -> 403 is recorded as 403 Forbidden, not a misleading 301.
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


def _fetch_baseline(client, base_url):
    """Fetch the target root (following redirects) so candidate paths can be
    compared to it for soft-404 detection."""
    status, _headers, body = _fetch(client, base_url)
    if status is not None and status < 500:
        return normalized_body_hash(body)
    return None


def _check_path(client, base_url, path, baseline_hash):
    """Check a single path with content analysis; return a result dict or None."""
    url = base_url.rstrip("/") + path
    status, headers, body = _fetch(client, url)
    if status is None:
        return None
    if status not in STATUS_OF_INTEREST:
        return None

    # Prefer the real Content-Length header; fall back to the (capped) body size
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

    # Do not record genuine not-found responses (404) or soft-404s that are
    # byte-identical to the site baseline — those are the classic false
    # positives where a 200 used to be reported as "Exposed".
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


def run_python_directory_scanner(targets, max_workers=10):
    """Python-based directory/file enumeration using concurrent httpx requests.

    Each candidate path is fetched with a size-capped body, compared against
    the site baseline (soft-404 detection) and classified by the content
    analysis engine (category / access status / risk).
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
        try:
            with httpx.Client(
                headers=bypass_headers,
                timeout=10,
                verify=False,
                follow_redirects=False,
            ) as client:
                baseline_hash = _fetch_baseline(client, base_url)
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    fut_map = {
                        pool.submit(_check_path, client, base_url, p, baseline_hash): p
                        for p in ALL_PATHS
                    }
                    try:
                        for fut in as_completed(fut_map, timeout=120):
                            r = fut.result()
                            if r:
                                results.append(r)
                                found += 1
                    except TimeoutError:
                        # Keep whatever completed before the deadline
                        for fut in fut_map:
                            if fut.done() and not fut.cancelled():
                                try:
                                    r = fut.result()
                                    if r:
                                        results.append(r)
                                        found += 1
                                except Exception:
                                    pass
        except Exception as e:
            logger.warning("directory scan failed for %s: %s", target, e)
        logger.info("python directory scanner found %d entries for %s", found, target)

    return results


# ── Orchestrator ──────────────────────────────────────────────────────────

def run_directory_scan(targets):
    """Main directory scan entry point.
    Uses the pure-Python concurrent httpx scanner with content analysis
    (no external binary needed).
    """
    logger.info("Running Python directory scanner for %s", targets)
    return run_python_directory_scanner(targets)
