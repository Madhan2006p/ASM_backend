import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx

from .command_utils import (
    add_execution_error,
    dedupe_preserve_order,
    extract_hostnames,
)


# Known technology fingerprints for header/HTML-based detection
TECH_FINGERPRINTS = {
    # Web Servers
    "nginx": {
        "name": "Nginx",
        "category": "Web Server",
        "headers": {"server": r"nginx"},
    },
    "apache": {
        "name": "Apache HTTP Server",
        "category": "Web Server",
        "headers": {"server": r"apache"},
    },
    "iis": {
        "name": "Microsoft IIS",
        "category": "Web Server",
        "headers": {"server": r"iis", "x-powered-by": r"asp\.net"},
    },
    "caddy": {
        "name": "Caddy",
        "category": "Web Server",
        "headers": {"server": r"caddy"},
    },
    "openresty": {
        "name": "OpenResty",
        "category": "Web Server",
        "headers": {"server": r"openresty"},
    },
    "gunicorn": {
        "name": "Gunicorn",
        "category": "Web Server",
        "headers": {"server": r"gunicorn"},
    },
    "cloudflare": {
        "name": "Cloudflare",
        "category": "CDN",
        "headers": {"server": r"cloudflare", "cf-ray": r"."},
    },
    # Web Frameworks
    "django": {
        "name": "Django",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"django"},
        "cookies": {"csrftoken": r"."},
    },
    "flask": {
        "name": "Flask",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"flask|werkzeug"},
        "cookies": {"session": r"."},
    },
    "express": {
        "name": "Express",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"express"},
    },
    "rails": {
        "name": "Ruby on Rails",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"rails|ruby"},
        "cookies": {"_session": r"."},
    },
    "laravel": {
        "name": "Laravel",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"laravel"},
        "cookies": {"laravel_session": r"."},
    },
    "spring": {
        "name": "Spring Boot",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"spring|java"},
        "cookies": {"JSESSIONID": r"."},
    },
    "nextjs": {
        "name": "Next.js",
        "category": "JavaScript Framework",
        "headers": {"x-powered-by": r"next\.js"},
    },
    "nuxt": {
        "name": "Nuxt.js",
        "category": "JavaScript Framework",
        "headers": {"x-powered-by": r"nuxt"},
    },
    # CMS
    "wordpress": {
        "name": "WordPress",
        "category": "CMS",
        "cookies": {"wordpress": r".", "wordpress_logged_in": r"."},
        "html": r"wp-content|wp-includes|wp-json",
    },
    "drupal": {
        "name": "Drupal",
        "category": "CMS",
        "headers": {"x-generator": r"drupal"},
        "cookies": {"drupal": r"."},
    },
    "joomla": {
        "name": "Joomla",
        "category": "CMS",
        "cookies": {"joomla": r"."},
    },
    # JavaScript Frameworks
    "react": {
        "name": "React",
        "category": "JavaScript Framework",
        "html": r"react\.js|react-dom|data-reactroot|__NEXT_DATA__|_next/static",
    },
    "angular": {
        "name": "Angular",
        "category": "JavaScript Framework",
        "html": r"ng-app|ng-version|angular\.js",
    },
    "vue": {
        "name": "Vue.js",
        "category": "JavaScript Framework",
        "html": r"vue\.js|vue\.min\.js|__VUE__|data-v-",
    },
    "jquery": {
        "name": "jQuery",
        "category": "JavaScript Library",
        "html": r"jquery\.js|jquery-|jquery\.min\.js",
    },
    "bootstrap": {
        "name": "Bootstrap",
        "category": "CSS Framework",
        "html": r"bootstrap\.css|bootstrap-|bootstrap\.min\.css",
    },
    "tailwind": {
        "name": "Tailwind CSS",
        "category": "CSS Framework",
        "html": r"tailwindcss|@tailwind",
    },
    # Analytics
    "google-analytics": {
        "name": "Google Analytics",
        "category": "Analytics",
        "html": r"google-analytics\.com|gtag\(|ga\('create'",
    },
    "hotjar": {
        "name": "Hotjar",
        "category": "Analytics",
        "html": r"hotjar\.com|hj\.js",
    },
    # Other
    "php": {
        "name": "PHP",
        "category": "Programming Language",
        "headers": {"x-powered-by": r"php"},
        "cookies": {"PHPSESSID": r"."},
    },
    "java": {
        "name": "Java",
        "category": "Programming Language",
        "cookies": {"JSESSIONID": r"."},
    },
    "asp.net": {
        "name": "ASP.NET",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"asp\.net", "x-aspnet-version": r"."},
        "cookies": {"asp.net_sessionid": r".", "aspsessionid": r"."},
    },
    "perl": {
        "name": "Perl",
        "category": "Programming Language",
        "headers": {"x-powered-by": r"perl"},
    },
    "python": {
        "name": "Python",
        "category": "Programming Language",
        "headers": {"server": r"python|gunicorn|uwsgi"},
    },
    "ruby": {
        "name": "Ruby",
        "category": "Programming Language",
        "headers": {"server": r"ruby|passenger|puma|unicorn"},
    },
    "node.js": {
        "name": "Node.js",
        "category": "Runtime",
        "headers": {"x-powered-by": r"node"},
    },
    "tomcat": {
        "name": "Apache Tomcat",
        "category": "Application Server",
        "headers": {"server": r"tomcat"},
    },
    "jenkins": {
        "name": "Jenkins",
        "category": "CI/CD",
        "headers": {"x-jenkins": r".", "x-hudson": r"."},
    },
    "gitlab": {
        "name": "GitLab",
        "category": "DevOps",
        "headers": {"x-gitlab": r"."},
    },
    "grafana": {
        "name": "Grafana",
        "category": "Monitoring",
        "headers": {"x-grafana": r"."},
    },
    "prometheus": {
        "name": "Prometheus",
        "category": "Monitoring",
        "html": r"prometheus|/api/v1/query",
    },
    "varnish": {
        "name": "Varnish",
        "category": "Cache",
        "headers": {"via": r"varnish", "x-varnish": r"."},
    },
    "squid": {
        "name": "Squid",
        "category": "Proxy",
        "headers": {"server": r"squid", "x-squid": r"."},
    },
    "haproxy": {
        "name": "HAProxy",
        "category": "Load Balancer",
        "headers": {"x-served-by": r"haproxy"},
    },
}


def probe_and_detect(url):
    """Probe a single URL and detect technologies."""
    try:
        with httpx.Client(verify=False, timeout=10, follow_redirects=True) as client:
            resp = client.get(url)
    except Exception:
        return None

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    set_cookie = headers_lower.get("set-cookie", "")
    body = resp.text or ""
    html_lower = body.lower()
    title = ""
    title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()[:200]

    detected = {}
    for key, fingerprint in TECH_FINGERPRINTS.items():
        name = fingerprint["name"]
        cat = fingerprint["category"]

        # Check headers
        if "headers" in fingerprint:
            for header_name, pattern in fingerprint["headers"].items():
                header_val = headers_lower.get(header_name, "")
                if header_val and re.search(pattern, header_val, re.IGNORECASE):
                    detected.setdefault(cat, {})[name] = True
                    break

        # Check cookies
        if "cookies" in fingerprint and set_cookie:
            for cookie_name, pattern in fingerprint["cookies"].items():
                if re.search(cookie_name, set_cookie, re.IGNORECASE) and re.search(pattern, set_cookie, re.IGNORECASE):
                    detected.setdefault(cat, {})[name] = True
                    break

        # Check HTML
        if "html" in fingerprint:
            if re.search(fingerprint["html"], html_lower, re.IGNORECASE):
                detected.setdefault(cat, {})[name] = True

    # Flatten detected technologies
    all_techs = list(dict.fromkeys(
        tech for cat in detected.values() for tech in cat.keys()
    ))

    if not all_techs:
        return None

    parsed_host = urlparse(url).hostname or url
    return {
        "url": url,
        "host": parsed_host,
        "technologies": all_techs,
        "categories": {cat: list(techs.keys()) for cat, techs in detected.items()},
        "title": title,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }


def run_whatweb(targets, max_workers=10):
    """
    Whatweb-like technology detection scanner.
    Uses HTTP headers, cookies, and HTML content to identify technologies.
    """
    if isinstance(targets, str):
        targets = [targets]

    # Normalize URLs
    urls = []
    for t in targets[:20]:
        t = t.strip()
        if not t:
            continue
        if t.startswith("http://") or t.startswith("https://"):
            urls.append(t)
        else:
            urls.append(f"https://{t}")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_map = {pool.submit(probe_and_detect, u): u for u in urls}
        for fut in as_completed(fut_map):
            try:
                r = fut.result()
                if r:
                    results.append(r)
            except Exception:
                pass

    return results


def run_whatweb_scan(target_str):
    """
    Run whatweb-like scan and return standardized output.
    """
    parsed_output = {
        "total_detected": 0,
        "hosts": [],
        "technologies_summary": {},
    }

    try:
        results = run_whatweb([target_str])
    except Exception as e:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_detected": 0,
                "hosts": [],
                "technologies_summary": {},
                "error": str(e),
            },
        }

    tech_counter = {}
    for r in results:
        host = r["host"]
        techs = r["technologies"]
        for t in techs:
            tech_counter[t] = tech_counter.get(t, 0) + 1
        parsed_output["hosts"].append(r)

    parsed_output["total_detected"] = len(results)
    # Sort technologies by frequency
    parsed_output["technologies_summary"] = dict(
        sorted(tech_counter.items(), key=lambda x: -x[1])
    )

    return {
        "raw_output": str(results),
        "parsed_output": parsed_output,
    }
