import logging
from urllib.parse import urlparse

from .command_utils import extract_hostnames

logger = logging.getLogger(__name__)

# Try to import Wappalyzer (supports both package names)
WAPPALYZER_AVAILABLE = False
Wappalyzer = None
WebPage = None

try:
    from wappalyzer import Wappalyzer as WappalyzerCls, WebPage as WebPageCls
    Wappalyzer = WappalyzerCls
    WebPage = WebPageCls
    WAPPALYZER_AVAILABLE = True
except ImportError:
    try:
        from Wappalyzer import Wappalyzer as WappalyzerCls, WebPage as WebPageCls
        Wappalyzer = WappalyzerCls
        WebPage = WebPageCls
        WAPPALYZER_AVAILABLE = True
    except ImportError:
        pass


# Fallback technology fingerprints when Wappalyzer library is not available
FALLBACK_TECH_FINGERPRINTS = {
    "nginx": {"name": "Nginx", "category": "Web Server"},
    "apache": {"name": "Apache HTTP Server", "category": "Web Server"},
    "cloudflare": {"name": "Cloudflare", "category": "CDN"},
    "openresty": {"name": "OpenResty", "category": "Web Server"},
    "iis": {"name": "Microsoft IIS", "category": "Web Server"},
    "caddy": {"name": "Caddy", "category": "Web Server"},
    "gunicorn": {"name": "Gunicorn", "category": "Web Server"},
    "express": {"name": "Express", "category": "Web Framework"},
    "django": {"name": "Django", "category": "Web Framework"},
    "flask": {"name": "Flask", "category": "Web Framework"},
    "rails": {"name": "Ruby on Rails", "category": "Web Framework"},
    "laravel": {"name": "Laravel", "category": "Web Framework"},
    "wordpress": {"name": "WordPress", "category": "CMS"},
    "drupal": {"name": "Drupal", "category": "CMS"},
    "joomla": {"name": "Joomla", "category": "CMS"},
    "react": {"name": "React", "category": "JavaScript Framework"},
    "angular": {"name": "Angular", "category": "JavaScript Framework"},
    "vue": {"name": "Vue.js", "category": "JavaScript Framework"},
    "nextjs": {"name": "Next.js", "category": "JavaScript Framework"},
    "jquery": {"name": "jQuery", "category": "JavaScript Library"},
    "bootstrap": {"name": "Bootstrap", "category": "CSS Framework"},
    "tailwind": {"name": "Tailwind CSS", "category": "CSS Framework"},
    "php": {"name": "PHP", "category": "Programming Language"},
    "java": {"name": "Java", "category": "Programming Language"},
    "python": {"name": "Python", "category": "Programming Language"},
    "node.js": {"name": "Node.js", "category": "Runtime"},
    "tomcat": {"name": "Apache Tomcat", "category": "Application Server"},
    "jenkins": {"name": "Jenkins", "category": "CI/CD"},
    "gitlab": {"name": "GitLab", "category": "DevOps"},
    "grafana": {"name": "Grafana", "category": "Monitoring"},
    "prometheus": {"name": "Prometheus", "category": "Monitoring"},
}


def run_wappalyzer(targets):
    """Detect web technologies using python-Wappalyzer library or fallback."""
    if isinstance(targets, str):
        targets = [targets]

    if WAPPALYZER_AVAILABLE:
        return _run_wappalyzer_library(targets)
    else:
        logger.info("Wappalyzer library not available, using header-based fallback")
        return _run_fallback_tech_detection(targets)


def _run_wappalyzer_library(targets):
    """Run Wappalyzer library for technology detection."""
    try:
        wappalyzer = Wappalyzer.latest()
    except Exception as e:
        logger.warning("Failed to initialize Wappalyzer: %s", e)
        return _run_fallback_tech_detection(targets)

    results = []
    for t in targets[:10]:
        url = t if (t.startswith("http://") or t.startswith("https://")) else f"https://{t}"
        try:
            webpage = WebPage.new_from_url(url, timeout=15)
            techs = wappalyzer.analyze(webpage)
            if techs:
                host = urlparse(url).hostname or t
                results.append({
                    "domain": host,
                    "url": url,
                    "technologies": sorted(techs),
                })
        except Exception as e:
            logger.debug("Wappalyzer failed for %s: %s", url, e)

    return _format_output(results)


def _run_fallback_tech_detection(targets):
    """Use httpx to probe targets and detect technologies from headers/HTML."""
    import re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    import httpx

    results = []

    def probe_and_detect(t):
        url = t if (t.startswith("http://") or t.startswith("https://")) else f"https://{t}"
        try:
            with httpx.Client(verify=False, timeout=10, follow_redirects=True) as client:
                resp = client.get(url)
        except Exception:
            return None

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        set_cookie = headers_lower.get("set-cookie", "")
        body = (resp.text or "").lower()
        title = ""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text or "", re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()[:200]

        detected = {}
        for key, info in FALLBACK_TECH_FINGERPRINTS.items():
            name = info["name"]
            cat = info["category"]

            # Check server header
            server = headers_lower.get("server", "")
            if key in server.lower():
                detected.setdefault(cat, {})[name] = True

            # Check X-Powered-By
            xpb = headers_lower.get("x-powered-by", "")
            if key in xpb.lower():
                detected.setdefault(cat, {})[name] = True

            # Check cookies
            if key in set_cookie.lower():
                detected.setdefault(cat, {})[name] = True

            # Check HTML
            if key in body or name.lower() in body:
                detected.setdefault(cat, {})[name] = True

        all_techs = list(dict.fromkeys(
            tech for cat in detected.values() for tech in cat.keys()
        ))

        if not all_techs:
            return None

        host = urlparse(url).hostname or t
        return {
            "domain": host,
            "url": url,
            "technologies": all_techs,
            "title": title,
            "status_code": resp.status_code,
        }

    with ThreadPoolExecutor(max_workers=10) as pool:
        fut_map = {pool.submit(probe_and_detect, t): t for t in targets[:20]}
        for fut in as_completed(fut_map):
            try:
                r = fut.result()
                if r:
                    results.append(r)
            except Exception:
                pass

    return _format_output(results)


def _format_output(results):
    """Format the technology detection results into standard output format."""
    tech_counter = {}
    hosts = []

    for r in results:
        host = r.get("domain", "")
        techs = r.get("technologies", [])
        for t in techs:
            tech_counter[t] = tech_counter.get(t, 0) + 1
        hosts.append(r)

    parsed_output = {
        "total_detected": len(results),
        "hosts": hosts,
        "technologies_summary": dict(
            sorted(tech_counter.items(), key=lambda x: -x[1])
        ),
    }

    return {
        "raw_output": str(results),
        "parsed_output": parsed_output,
    }
