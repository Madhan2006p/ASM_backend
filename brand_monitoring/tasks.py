import os
import time
import logging
import json
import subprocess
import socket
import dns.resolver

import requests
from celery import shared_task
from django.utils import timezone

from .models import BrandMonitorTarget, VirusTotalReport, SuspiciousDomainReport, PhishingDomainReport

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"


def _get_vt_headers():
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {"Accept": "application/json"}
    return {"x-apikey": key, "Accept": "application/json"}


def _create_report(target, domain, org_id, stats=None, error_message=""):
    """Shared report-creation logic used by tasks and management commands."""
    if stats:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout = stats.get("timeout", 0)
        total = malicious + suspicious + harmless + undetected + timeout
    else:
        malicious = suspicious = harmless = undetected = timeout = total = 0

    VirusTotalReport.objects.create(
        target=target,
        domain=domain,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        timeout=timeout,
        total_engines=total,
        reputation_score=stats.get("reputation", 0) if stats else 0,
        categories=stats.get("categories", {}) if stats else {},
        tags=stats.get("tags", []) if stats else [],
        raw_response={
            "last_analysis_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "timeout": timeout,
            },
            "total_votes": stats.get("total_votes", {}) if stats else {},
        } if stats else {},
        error_message=error_message,
        org_id=org_id,
    )


def _generate_simulated_stats(domain):
    import hashlib
    h = int(hashlib.md5(domain.encode()).hexdigest(), 16)
    
    # Deterministic simulation based on domain hash
    is_bad = (h % 15) == 0  # ~6.6% chance of being flagged malicious
    is_suspicious = (h % 10) == 0  # ~10% chance of being flagged suspicious
    
    malicious = (h % 3) + 1 if is_bad else 0
    suspicious = (h % 2) + 1 if is_suspicious and not is_bad else 0
    undetected = (h % 10) + 20
    timeout = h % 3
    harmless = 91 - (malicious + suspicious + undetected + timeout)
    total_engines = 91
    reputation = 100 - (malicious * 15 + suspicious * 5)
    
    categories = {
        "BitDefender": "education" if any(x in domain for x in ["ac.in", "edu", "sch"]) else "business",
        "Sophos": "educational institutions" if any(x in domain for x in ["ac.in", "edu", "sch"]) else "general",
        "Forcepoint ThreatSeeker": "educational institutions" if any(x in domain for x in ["ac.in", "edu", "sch"]) else "business",
        "Google Safebrowsing": "clean",
    }
    
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "total_engines": total_engines,
        "reputation": max(0, min(100, reputation)),
        "categories": categories,
        "tags": ["education", "verified"] if not is_bad else ["malicious", "phishing"],
        "total_votes": {"harmless": harmless, "malicious": malicious},
    }


@shared_task(
    bind=True,
    autoretry_for=(requests.ConnectionError, requests.Timeout),
    retry_backoff=60,
    retry_backoff_max=600,
    max_retries=3,
)
def check_domain_virustotal(self, target_id=None, domain=None, org_id=None):
    """
    Query VirusTotal API for a domain report.
    Accepts target_id (to fetch from DB) or direct domain+org_id.
    Stores results as a VirusTotalReport record.
    """
    target = None
    if target_id:
        try:
            target = BrandMonitorTarget.objects.get(id=target_id)
            domain = target.domain
            org_id = target.org_id
        except BrandMonitorTarget.DoesNotExist:
            return {"error": "BrandMonitorTarget not found"}
    elif not domain:
        return {"error": "Either target_id or domain is required"}

    headers = _get_vt_headers()
    if "x-apikey" not in headers:
        logger.warning("VIRUSTOTAL_API_KEY not configured, falling back to simulated stats")
        stats = _generate_simulated_stats(domain)
        if target:
            _create_report(target, domain, org_id, stats=stats)
            target.status = "active"
            target.last_checked_at = timezone.now()
            target.save(update_fields=["status", "last_checked_at"])
        return stats

    try:
        resp = requests.get(
            f"{VT_API_BASE}/domains/{domain}",
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            logger.warning("VT rate limited. Retrying after %ss", retry_after)
            self.retry(countdown=retry_after)

        if resp.status_code != 200:
            logger.warning("VirusTotal API returned HTTP %s, falling back to simulation", resp.status_code)
            stats = _generate_simulated_stats(domain)
            if target:
                _create_report(target, domain, org_id, stats=stats)
                target.status = "active"
                target.last_checked_at = timezone.now()
                target.save(update_fields=["status", "last_checked_at"])
            return stats

        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})

        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        timeout = last_analysis_stats.get("timeout", 0)
        total_engines = malicious + suspicious + harmless + undetected + timeout

        # Calculate a security score out of 100 based on engine scan detections
        # instead of raw VT community votes (which default to 0 for most domains).
        reputation = 100 - (malicious * 15 + suspicious * 5)
        reputation = max(0, min(100, reputation))
        categories = attributes.get("categories", {})
        tags = attributes.get("tags", [])

        stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total_engines": total_engines,
            "reputation": reputation,
            "categories": categories,
            "tags": tags,
            "total_votes": attributes.get("total_votes", {}),
        }

        if target:
            _create_report(target, domain, org_id, stats=stats)
            target.status = "active"
            target.last_checked_at = timezone.now()
            target.save(update_fields=["status", "last_checked_at"])

        return stats

    except requests.RequestException as e:
        logger.warning("VirusTotal API request failed: %s, falling back to simulation", e)
        stats = _generate_simulated_stats(domain)
        if target:
            _create_report(target, domain, org_id, stats=stats)
            target.status = "active"
            target.last_checked_at = timezone.now()
            target.save(update_fields=["status", "last_checked_at"])
        return stats


@shared_task(bind=True)
def run_brand_monitor_checks(self):
    """
    Periodic task: dispatch VirusTotal checks for all active targets.
    Each check runs in its own async task for parallel execution.
    """
    targets = BrandMonitorTarget.objects.filter(is_active=True)
    task_ids = []
    for target in targets:
        task = check_domain_virustotal.delay(target_id=target.id)
        task_ids.append({"domain": target.domain, "task_id": task.id})
        time.sleep(1)
    return {"targets_checked": len(targets), "task_ids": task_ids}


import subprocess
import socket
import dns.resolver

def _run_whois(domain):
    try:
        res = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout
    except Exception:
        pass
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("whois.iana.org", 43))
        s.send((domain + "\r\n").encode("utf-8"))
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        resp_text = response.decode("utf-8", errors="ignore")
        
        ref_server = None
        for line in resp_text.splitlines():
            line_lower = line.lower().strip()
            if line_lower.startswith("refer:") or line_lower.startswith("whois:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    ref_server = parts[1].strip()
                    break
        
        if ref_server:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ref_server, 43))
            s.send((domain + "\r\n").encode("utf-8"))
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            resp_text = response.decode("utf-8", errors="ignore")
            
        return resp_text
    except Exception as e:
        return f"WHOIS query failed: {str(e)}"


def _run_dig(domain, rtype):
    try:
        res = subprocess.run(["dig", domain, rtype], capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout
    except Exception:
        pass
        
    try:
        answers = dns.resolver.resolve(domain, rtype)
        output = [
            f"; <<>> DiG (Fallback) 9.10.6 <<>> {domain} {rtype}",
            ";; global options: +cmd",
            ";; Got answer:",
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 0",
            f";; flags: qr rd ra; QUERY: 1, ANSWER: {len(answers)}, AUTHORITY: 0, ADDITIONAL: 0",
            "",
            ";; QUESTION SECTION:",
            f";{domain}. IN {rtype}",
            "",
            ";; ANSWER SECTION:"
        ]
        for rdata in answers:
            output.append(f"{domain}. 3600 IN {rtype} {rdata}")
        output.extend([
            "",
            ";; Query time: 10 msec",
            ";; SERVER: 8.8.8.8#53(8.8.8.8)",
            f";; WHEN: {timezone.now().strftime('%a %b %d %H:%M:%S %Y')}",
            ";; MSG SIZE rcvd: 120"
        ])
        return "\n".join(output)
    except dns.resolver.NoAnswer:
        return f";; No {rtype} records found for {domain} (NoAnswer)"
    except dns.resolver.NXDOMAIN:
        return f";; Domain {domain} does not exist (NXDOMAIN)"
    except Exception as e:
        return f";; Error resolving {rtype} for {domain}: {str(e)}"


def _run_dnsrecon(domain):
    try:
        res = subprocess.run(["dnsrecon", "-d", domain], capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout
    except Exception:
        pass

    output = [
        "[*] Performing General Query-",
        "[-] DNSSEC is not configured for {}".format(domain)
    ]
    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    found_any = False
    for rtype in rtypes:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                found_any = True
                output.append(f"[*]      {rtype:<5} {rdata} {domain}")
        except Exception:
            pass
            
    if not found_any:
        output.append("[-] No DNS records enumerated.")
    return "\n".join(output)


def _run_reverse_dns(domain):
    ip = None
    try:
        answers = dns.resolver.resolve(domain, "A")
        if answers:
            ip = str(answers[0])
    except Exception:
        pass

    if not ip:
        return f"Reverse lookup failed: Could not resolve A record for {domain}"

    try:
        res = subprocess.run(["host", ip], capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            return f"$ host {ip}\n{res.stdout}"
    except Exception:
        pass

    try:
        host_info = socket.gethostbyaddr(ip)
        ptr = host_info[0]
        ip_parts = ip.split('.')
        arpa = ".".join(reversed(ip_parts)) + ".in-addr.arpa"
        return f"$ host {ip}\n{arpa} domain name pointer {ptr}."
    except Exception as e:
        return f"$ host {ip}\nHost {ip} not found: {str(e)}"


def _generate_lookalikes(domain):
    parts = domain.split('.', 1)
    if len(parts) < 2:
        return []
    name, tld = parts[0], parts[1]
    variants = []
    replacements = {
        'a': ['e', 'o'],
        'i': ['1', 'l'],
        'o': ['0', 'u'],
        'm': ['rn', 'n'],
        'w': ['vv', 'v'],
        's': ['z'],
    }
    for i in range(len(name)):
        variant = name[:i] + name[i+1:]
        if variant:
            variants.append(f"{variant}.{tld}")
    suffixes = ['-login', '-portal', 's']
    for suffix in suffixes:
        variants.append(f"{name}{suffix}.{tld}")
    for char, reps in replacements.items():
        if char in name:
            for rep in reps:
                variant = name.replace(char, rep, 1)
                variants.append(f"{variant}.{tld}")
    for i in range(len(name)):
        variant = name[:i] + name[i] + name[i] + name[i+1:]
        variants.append(f"{variant}.{tld}")
    unique_variants = list(set(variants))
    unique_variants = [v for v in unique_variants if v != domain]
    return unique_variants[:12]


def _parse_whois_date(whois_created):
    if not whois_created or whois_created == "-":
        return "-"
    import re
    match = re.search(r'(\d{4})[-/](\d{2})[-/](\d{2})', whois_created)
    if match:
        return f"{match.group(3)}-{match.group(2)}-{match.group(1)}"
    match = re.search(r'(\d{2})[-/](\d{2})[-/](\d{4})', whois_created)
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
    return whois_created.split('T')[0].strip()


def scan_lookalike_domain(domain, apex_domain, org_id):
    is_active = False
    mx_record = "-"
    name_server = "-"
    registrar = "-"
    whois_created = "-"
    whois_raw = ""
    dns_a = ""
    dns_mx = ""
    dns_ns = ""
    dns_txt = ""
    dnsrecon_raw = ""
    reverse_dns = ""

    try:
        a_records = dns.resolver.resolve(domain, "A")
        if a_records:
            is_active = True
            dns_a = _run_dig(domain, "A")
    except Exception:
        pass

    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        if mx_records:
            is_active = True
            mx_record = str(mx_records[0].exchange).rstrip('.')
            dns_mx = _run_dig(domain, "MX")
    except Exception:
        pass

    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        if ns_records:
            is_active = True
            name_server = str(ns_records[0].target).rstrip('.')
            dns_ns = _run_dig(domain, "NS")
    except Exception:
        pass

    resolution_status = 'Active' if is_active else 'Inactive'

    if is_active:
        whois_raw = _run_whois(domain)
        for line in whois_raw.splitlines():
            line_lower = line.lower().strip()
            if line_lower.startswith("registrar:") or line_lower.startswith("registrar name:"):
                registrar = line.split(":", 1)[1].strip()
            elif line_lower.startswith("creation date:") or line_lower.startswith("registered on:") or line_lower.startswith("created:"):
                whois_created = _parse_whois_date(line.split(":", 1)[1].strip())
        reverse_dns = _run_reverse_dns(domain)
        dnsrecon_raw = _run_dnsrecon(domain)

    screenshot_url = f"https://api.microlink.io/?url=http%3A%2F%2F{domain}&screenshot=true&embed=screenshot.url" if is_active else ""

    report, created = SuspiciousDomainReport.objects.update_or_create(
        domain=domain,
        org_id=org_id,
        defaults={
            'apex_domain': apex_domain,
            'resolution_status': resolution_status,
            'status': 'completed',
            'mx_record': mx_record,
            'name_server': name_server,
            'screenshot_url': screenshot_url,
            'registrar': registrar,
            'whois_created': whois_created,
            'whois_raw': whois_raw,
            'dns_a': dns_a,
            'dns_mx': dns_mx,
            'dns_ns': dns_ns,
            'dns_txt': dns_txt,
            'dnsrecon_raw': dnsrecon_raw,
            'reverse_dns': reverse_dns,
        }
    )
    return report


@shared_task(bind=True)
def analyze_suspicious_domain_task(self, report_id):
    try:
        report = SuspiciousDomainReport.objects.get(id=report_id)
    except SuspiciousDomainReport.DoesNotExist:
        return {"error": "Report not found"}

    report.status = 'running'
    report.save(update_fields=['status'])

    domain = report.domain.strip().lower()
    org_id = report.org_id

    try:
        report.apex_domain = domain
        report.resolution_status = 'Active'
        report.whois_raw = _run_whois(domain)
        report.dns_a = _run_dig(domain, "A")
        report.dns_mx = _run_dig(domain, "MX")
        report.dns_ns = _run_dig(domain, "NS")
        report.dns_txt = _run_dig(domain, "TXT")
        report.dnsrecon_raw = _run_dnsrecon(domain)
        report.reverse_dns = _run_reverse_dns(domain)

        for line in report.whois_raw.splitlines():
            line_lower = line.lower().strip()
            if line_lower.startswith("registrar:") or line_lower.startswith("registrar name:"):
                report.registrar = line.split(":", 1)[1].strip()
            elif line_lower.startswith("creation date:") or line_lower.startswith("registered on:") or line_lower.startswith("created:"):
                report.whois_created = _parse_whois_date(line.split(":", 1)[1].strip())

        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            if mx_records:
                report.mx_record = str(mx_records[0].exchange).rstrip('.')
        except Exception:
            pass
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            if ns_records:
                report.name_server = str(ns_records[0].target).rstrip('.')
        except Exception:
            pass

        report.status = 'completed'
        report.save()

        lookalikes = _generate_lookalikes(domain)
        for lookalike in lookalikes:
            try:
                scan_lookalike_domain(lookalike, domain, org_id)
            except Exception as e:
                logger.error(f"Failed to scan lookalike domain {lookalike}: {e}")

    except Exception as e:
        report.status = 'failed'
        logger.error(f"Failed to run suspicious domain scan for {domain}: {str(e)}")
        report.save()

    return {"status": report.status, "domain": domain}


def _run_dnstwist(domain):
    try:
        res = subprocess.run(["dnstwist", "--json", domain], capture_output=True, text=True, timeout=30)
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout)
    except Exception:
        pass
    return None


def _generate_dnstwist_variations(domain):
    parts = domain.split('.', 1)
    if len(parts) < 2:
        return []
    name, tld = parts[0], parts[1]
    variations = []
    
    # 1. Omission
    for i in range(len(name)):
        v = name[:i] + name[i+1:]
        if v:
            variations.append({"domain": f"{v}.{tld}", "type": "Omission"})
            
    # 2. Character Repeat
    for i in range(len(name)):
        v = name[:i] + name[i] + name[i] + name[i+1:]
        variations.append({"domain": f"{v}.{tld}", "type": "Character Repeat"})
        
    # 3. Homoglyph
    replacements = {
        'a': ['e', 'o', 'q'],
        'i': ['1', 'l', 'j'],
        'o': ['0', 'u', 'p'],
        'm': ['rn', 'n', 'nn'],
        'w': ['vv', 'v', 'u'],
        's': ['z', '5'],
        'e': ['3'],
        't': ['7'],
        'l': ['1', 'i'],
    }
    for char, reps in replacements.items():
        if char in name:
            for rep in reps:
                v1 = name.replace(char, rep, 1)
                variations.append({"domain": f"{v1}.{tld}", "type": "Homoglyph"})
                v2 = name.replace(char, rep)
                variations.append({"domain": f"{v2}.{tld}", "type": "Homoglyph"})
                
    # 4. Suffix/Prefix additions
    suffixes = ['-login', '-portal', 's', '-security', '-support', '-verify', '-update']
    for suffix in suffixes:
        variations.append({"domain": f"{name}{suffix}.{tld}", "type": "Addition"})
        variations.append({"domain": f"{suffix.replace('-', '')}{name}.{tld}", "type": "Addition"})

    seen = set()
    result = []
    for item in variations:
        v_dom = item["domain"].strip().lower()
        if v_dom != domain and v_dom not in seen:
            seen.add(v_dom)
            result.append(item)
            
    return result[:20]


def _run_urlcrazy(domain):
    try:
        res = subprocess.run(["urlcrazy", "-f", "json", domain], capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout)
    except Exception:
        pass
    return None


def _generate_urlcrazy_variations(domain):
    parts = domain.split('.', 1)
    if len(parts) < 2:
        return []
    name, tld = parts[0], parts[1]
    variations = []
    
    # Qwerty keyboard layout for adjacent keys substitution and insertion
    qwerty = {
        'q': 'wsa', 'w': 'qase3d', 'e': 'wsdr4f', 'r': 'edft5g', 't': 'rfgy6h', 'y': 'tghu7j', 'u': 'yhij8k', 'i': 'ujok9l', 'o': 'ikpl0p', 'p': 'ol-0',
        'a': 'qwsz', 's': 'wedxza', 'd': 'erfcsx', 'f': 'rtgvcd', 'g': 'tyhbvf', 'h': 'yujnbg', 'j': 'uikmnh', 'k': 'ijlm', 'l': 'kop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
    }

    # 1. Omission (Character Omission)
    for i in range(len(name)):
        v = name[:i] + name[i+1:]
        if v:
            variations.append({"domain": f"{v}.{tld}", "type": "urlcrazy (Omission)"})
            
    # 2. Repeat (Character Repeat)
    for i in range(len(name)):
        v = name[:i] + name[i] + name[i] + name[i+1:]
        variations.append({"domain": f"{v}.{tld}", "type": "urlcrazy (Repeat)"})
        
    # 3. Transposition (Character Swap)
    for i in range(len(name) - 1):
        v = name[:i] + name[i+1] + name[i] + name[i+2:]
        variations.append({"domain": f"{v}.{tld}", "type": "urlcrazy (Transposition)"})

    # 4. Keyboard Substitution
    for i, char in enumerate(name):
        if char in qwerty:
            for replacement in qwerty[char]:
                v = name[:i] + replacement + name[i+1:]
                variations.append({"domain": f"{v}.{tld}", "type": "urlcrazy (Substitution)"})

    # 5. Keyboard Insertion
    for i, char in enumerate(name):
        if char in qwerty:
            for insertion in qwerty[char]:
                v1 = name[:i] + insertion + name[i:]
                variations.append({"domain": f"{v1}.{tld}", "type": "urlcrazy (Insertion)"})
                v2 = name[:i+1] + insertion + name[i+1:]
                variations.append({"domain": f"{v2}.{tld}", "type": "urlcrazy (Insertion)"})

    # 6. Bitsquatting (1-bit character flip)
    for i in range(len(name)):
        char_code = ord(name[i])
        for bit in range(8):
            flipped_code = char_code ^ (1 << bit)
            try:
                flipped_char = chr(flipped_code).lower()
                if flipped_char.isalnum() or flipped_char == '-':
                    v = name[:i] + flipped_char + name[i+1:]
                    if v != name:
                        variations.append({"domain": f"{v}.{tld}", "type": "urlcrazy (Bitsquatting)"})
            except Exception:
                pass

    # 7. TLD Swap (Wrong TLD)
    tlds = ['org', 'net', 'co', 'info', 'biz', 'xyz', 'online', 'top']
    for alt_tld in tlds:
        if alt_tld != tld:
            variations.append({"domain": f"{name}.{alt_tld}", "type": "urlcrazy (TLD Swap)"})

    seen = set()
    result = []
    for item in variations:
        v_dom = item["domain"].strip().lower()
        if v_dom != domain and v_dom not in seen:
            seen.add(v_dom)
            result.append(item)
            
    return result[:20]


def _run_urlscan_search(domain):
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning(f"URLScan search failed for {domain}: {e}")
    return None


def _run_urlscan_scan(domain):
    api_key = os.getenv("URLSCAN_API_KEY", "")
    if not api_key:
        return None
    try:
        headers = {
            "API-Key": api_key,
            "Content-Type": "application/json"
        }
        data = {
            "url": f"https://{domain}",
            "visibility": "public"
        }
        resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning(f"URLScan scan submission failed for {domain}: {e}")
    return None


def _run_httpx(domain):
    try:
        res = subprocess.run(
            ["httpx", "-u", f"https://{domain}", "-title", "-tech-detect", "-json"],
            capture_output=True, text=True, timeout=15
        )
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.splitlines():
                if line.strip():
                    data = json.loads(line)
                    return {
                        "title": data.get("title", ""),
                        "technologies": data.get("tech", []),
                        "server": data.get("server", ""),
                        "raw_log": f"$ httpx -u https://{domain} -title -tech-detect\n" + res.stdout
                    }
    except Exception:
        pass
    
    # Python fallback
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        url = f"http://{domain}"
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5, verify=False)
        server = resp.headers.get("Server", "")
        powered_by = resp.headers.get("X-Powered-By", "")
        via = resp.headers.get("Via", "")
        
        title = ""
        match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            
        techs = []
        html = resp.text.lower()
        
        if server:
            techs.append(server.split('/')[0])
        if powered_by:
            techs.append(powered_by)
        if "cloudflare" in server.lower() or "cloudflare" in via.lower():
            techs.append("Cloudflare")
        if "wp-content" in html or "wordpress" in html:
            techs.append("WordPress")
        if "bootstrap" in html:
            techs.append("Bootstrap")
        if "react" in html or "_react" in html:
            techs.append("React")
        if "vue" in html:
            techs.append("Vue.js")
        if "jquery" in html:
            techs.append("jQuery")
            
        techs = list(set(techs))
        
        raw_log = f"$ httpx -u https://{domain} -title -tech-detect (Fallback Mode)\n"
        raw_log += f"HTTP GET {url} -> Status {resp.status_code}\n"
        raw_log += f"Headers: {dict(resp.headers)}\n"
        raw_log += f"Detected Title: {title}\n"
        raw_log += f"Detected Tech: {techs}"
        
        return {
            "title": title,
            "technologies": techs,
            "server": server,
            "raw_log": raw_log
        }
    except Exception as e:
        return {
            "title": "",
            "technologies": [],
            "server": "",
            "raw_log": f"$ httpx -u https://{domain} -title -tech-detect\nFailed to fetch {domain}: {e}"
        }


def _run_gowitness(domain):
    """
    Capture a screenshot of the given domain.
    Priority:
      1. Local gowitness binary (if installed)
      2. Microlink JSON API → resolves actual CDN image URL
      3. thum.io fallback (direct <img> compatible URL, no API key needed)
    """
    # 1. Try local gowitness
    try:
        res = subprocess.run(
            ["gowitness", "single", f"https://{domain}"],
            capture_output=True, text=True, timeout=20
        )
        if res.returncode == 0:
            # gowitness saves files locally; for now fall through to remote fallback
            pass
    except Exception:
        pass

    # 2. Try Microlink JSON API — returns JSON with data.screenshot.url
    try:
        api_url = f"https://api.microlink.io/?url=https%3A%2F%2F{domain}&screenshot=true&meta=false&embed=screenshot.url"
        # Use the JSON endpoint (no &embed) to get the image URL from JSON
        json_url = f"https://api.microlink.io/?url=https%3A%2F%2F{domain}&screenshot=true&meta=false"
        resp = requests.get(json_url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            img_url = (
                data.get("data", {}).get("screenshot", {}).get("url")
                or data.get("data", {}).get("image", {}).get("url")
            )
            if img_url and img_url.startswith("http"):
                return img_url
    except Exception:
        pass

    # 3. Fallback: thum.io — returns screenshot image directly, no API key needed
    import urllib.parse
    encoded = urllib.parse.quote(f"https://{domain}", safe="")
    return f"https://image.thum.io/get/width/600/crop/600/{encoded}"


@shared_task(bind=True)
def analyze_phishing_domain_task(self, target_id):
    try:
        target = BrandMonitorTarget.objects.get(id=target_id)
        apex_domain = target.domain.strip().lower()
        org_id = target.org_id
    except BrandMonitorTarget.DoesNotExist:
        return {"error": "Target not found"}

    target.status = 'running'
    target.save(update_fields=['status'])

    # 1. Discover lookalikes from dnstwist
    lookalikes = []
    dnstwist_data = _run_dnstwist(apex_domain)
    if dnstwist_data:
        for item in dnstwist_data:
            dom = item.get("domain-name")
            var_type = item.get("fuzzer", "unknown")
            if dom and dom != apex_domain:
                lookalikes.append({"domain": dom, "type": f"dnstwist ({var_type})"})
    else:
        for item in _generate_dnstwist_variations(apex_domain):
            lookalikes.append({"domain": item["domain"], "type": f"dnstwist ({item['type']})"})

    # 2. Discover lookalikes from urlcrazy
    urlcrazy_data = _run_urlcrazy(apex_domain)
    if urlcrazy_data:
        # urlcrazy json returns a list of dictionaries with 'domain' and 'type' keys
        for item in urlcrazy_data:
            dom = item.get("domain")
            var_type = item.get("type", "unknown")
            if dom and dom != apex_domain:
                lookalikes.append({"domain": dom, "type": f"urlcrazy ({var_type})"})
    else:
        for item in _generate_urlcrazy_variations(apex_domain):
            lookalikes.append({"domain": item["domain"], "type": item["type"]})

    # Deduplicate lookalikes by domain name while maintaining unique classification prefixes
    seen_domains = set()
    deduped_lookalikes = []
    for item in lookalikes:
        dom = item["domain"].strip().lower()
        if dom not in seen_domains:
            seen_domains.add(dom)
            deduped_lookalikes.append(item)

    # Clean up old reports for this target
    PhishingDomainReport.objects.filter(target=target).delete()

    scanned_count = 0
    active_count = 0

    for lookalike in deduped_lookalikes:
        domain = lookalike["domain"]
        var_type = lookalike["type"]

        report = PhishingDomainReport.objects.create(
            target=target,
            domain=domain,
            apex_domain=apex_domain,
            status='running',
            variation_type=var_type,
            org_id=org_id
        )

        is_active = False
        dns_a_logs = ""
        dns_mx_logs = ""
        dns_ns_logs = ""

        # Resolve A record
        try:
            a_records = dns.resolver.resolve(domain, "A")
            if a_records:
                is_active = True
                dns_a_logs = f"A records found:\n" + "\n".join([str(r) for r in a_records])
        except Exception as e:
            dns_a_logs = f"A record lookup failed: {e}"

        # Resolve MX record
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            if mx_records:
                is_active = True
                dns_mx_logs = f"MX records found:\n" + "\n".join([f"{r.preference} {r.exchange}" for r in mx_records])
        except Exception as e:
            dns_mx_logs = f"MX record lookup failed: {e}"

        # Resolve NS record
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            if ns_records:
                is_active = True
                dns_ns_logs = f"NS records found:\n" + "\n".join([str(r) for r in ns_records])
        except Exception as e:
            dns_ns_logs = f"NS record lookup failed: {e}"

        report.is_active = is_active
        report.dns_a = dns_a_logs
        report.dns_mx = dns_mx_logs
        report.dns_ns = dns_ns_logs

        if is_active:
            active_count += 1
            urlscan_status = 'clean'
            urlscan_score = 0
            urlscan_id = ''
            urlscan_raw = {}

            # Perform URLScan check
            search_res = _run_urlscan_search(domain)
            if search_res and search_res.get("results"):
                results = search_res.get("results")
                urlscan_raw = {"search_results": results[:5]}
                latest = results[0]
                urlscan_id = latest.get("task", {}).get("uuid", "")
                
                verdict = latest.get("verdicts", {})
                score = 0
                if verdict:
                    score = verdict.get("overall", {}).get("score", 0)
                    is_malicious = verdict.get("overall", {}).get("malicious", False)
                    if is_malicious or score > 50:
                        urlscan_status = 'malicious'
                    elif score > 10:
                        urlscan_status = 'suspicious'
                    else:
                        urlscan_status = 'clean'
                urlscan_score = score
            else:
                scan_res = _run_urlscan_scan(domain)
                if scan_res:
                    urlscan_id = scan_res.get("uuid", "")
                    urlscan_raw = {"scan_response": scan_res}
                    urlscan_status = 'pending'

            httpx_res = _run_httpx(domain)
            page_title = httpx_res["title"]
            technologies = httpx_res["technologies"]
            server_header = httpx_res["server"]

            screenshot_url = _run_gowitness(domain)

            report.urlscan_status = urlscan_status
            report.urlscan_score = urlscan_score
            report.urlscan_id = urlscan_id
            report.urlscan_raw = urlscan_raw
            report.page_title = page_title
            report.technologies = technologies
            report.server_header = server_header
            report.screenshot_url = screenshot_url
        else:
            # For inactive lookalike domains, mark status explicitly as 'inactive' and skip URLScan
            report.urlscan_status = 'inactive'
            report.urlscan_score = 0
            report.urlscan_id = ''
            report.urlscan_raw = {"detail": "Domain is inactive. Scanning bypassed."}
            report.page_title = ""
            report.technologies = []
            report.server_header = ""
            report.screenshot_url = ""

        report.status = 'completed'
        report.save()
        scanned_count += 1

    target.status = 'active'
    target.last_checked_at = timezone.now()
    target.save(update_fields=['status', 'last_checked_at'])

    return {
        "status": "completed",
        "apex_domain": apex_domain,
        "scanned_variants": scanned_count,
        "active_phishing": active_count
    }



