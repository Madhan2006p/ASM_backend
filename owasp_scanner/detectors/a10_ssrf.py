"""A10:2021 – Server-Side Request Forgery (SSRF) detector.

Detects:
- URL/redirect parameters that the server may fetch server-side
- Redirect chains to internal/private hosts (127.0.0.1, 169.254.x, 10.x, 192.168.x)
- Callback-style parameters (url, uri, next, callback, webhook, etc.)
"""

import re
from urllib.parse import urlencode, parse_qsl, urlparse, urlunparse

from .base import make_finding

CATEGORY = "A10:2021 – Server-Side Request Forgery (SSRF)"
RANK = 10

SSRF_URL_PARAMS = re.compile(
    r"\b(url|uri|link|src|source|dest|destination|redirect|return|next|callback|"
    r"feed|host|target|proxy|fetch|load|request|api|endpoint|webhook|forward|"
    r"import|file|path|image|img|media|document|attachment)\b",
    re.IGNORECASE,
)

INTERNAL_IP_PATTERNS = [
    r"^127\.", r"^10\.", r"^192\.168\.", r"^169\.254\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"^0\.", r"^\[?::1\]?$", r"^\[?fc", r"^\[?fd", r"^\[?fe80",
    r"^localhost", r"\.internal$", r"\.local$", r"\.corp$",
]


def _is_internal(hostname):
    h = (hostname or "").strip().lower().rstrip(".")
    return any(re.match(p, h) for p in INTERNAL_IP_PATTERNS)


def detect_a10(domain, host, base_urls, http):
    findings = []
    seen = set()

    def add(finding):
        key = (finding["vulnerability_id"], finding["subdomain"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    # 1. URL-fetching parameters present
    for base in list(base_urls)[:8]:
        parsed = urlparse(base)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            continue
        ssrf_params = [k for k in params if SSRF_URL_PARAMS.match(k)]
        if ssrf_params:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A10-SSRF-PARAMETERS",
                "MEDIUM", "CWE-918",
                f"Server-side URL-fetching parameters detected: {', '.join(ssrf_params)}",
                f"The endpoint {parsed.path or '/'} accepts URL-like parameters ({', '.join(ssrf_params)}). "
                f"If the server fetches these server-side without validation, attackers can reach "
                f"internal services.",
                "Validate all URL inputs against an allow-list of permitted hosts, block "
                "RFC1918/loopback/link-local ranges, and route outbound requests through a "
                "controlled egress proxy.",
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                "ssrf/url-parameters",
            ))
            # 2. Try a harmless internal redirect probe on the first such param
            for key in ssrf_params[:2]:
                probe_params = dict(params)
                probe_params[key] = "http://127.0.0.1/"
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_params)))
                try:
                    resp = http.get(probe_url, timeout=8, follow_redirects=True)
                except Exception:
                    continue
                final_host = urlparse(str(resp.url)).hostname or ""
                if _is_internal(final_host) and final_host != host:
                    add(make_finding(
                        domain, host, CATEGORY, RANK, "A10-SSRF-CONFIRMED",
                        "CRITICAL", "CWE-918",
                        f"SSRF confirmed — request routed to internal host {final_host}",
                        f"Sending a loopback URL via parameter '{key}' produced a request to "
                        f"internal host {final_host}, confirming the server fetches "
                        f"attacker-controlled URLs.",
                        "Block internal/private addresses at the application and network layer. "
                        "Never fetch user-supplied URLs without strict allow-lists.",
                        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                        "ssrf/confirmed",
                    ))
                break
            break

    # 3. Redirect chain to internal host
    for base in list(base_urls)[:5]:
        try:
            resp = http.get(base, timeout=8, follow_redirects=True)
        except Exception:
            continue
        final_host = urlparse(str(resp.url)).hostname or ""
        if _is_internal(final_host) and final_host != host:
            add(make_finding(
                domain, host, CATEGORY, RANK, "A10-REDIRECT-TO-INTERNAL",
                "HIGH", "CWE-918",
                f"Request redirects to internal host {final_host}",
                f"The URL {base} redirected to internal/loopback host {final_host}, a strong "
                f"SSRF indicator when triggered by user-controlled redirects.",
                "Validate redirect targets and block internal destinations for user-influenced "
                "redirects.",
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                "ssrf/redirect-internal",
            ))
            break

    return findings
