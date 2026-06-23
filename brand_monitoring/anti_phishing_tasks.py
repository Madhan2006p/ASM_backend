import logging
import requests
import urllib.parse
from django.utils import timezone
from .models import AntiPhishingScan

# Force IPv4 to prevent connection timeouts on DNS resolutions (AAAA records)
import socket
import urllib3.util.connection as urllib3_cn
urllib3_cn.allowed_gai_family = lambda: socket.AF_INET

logger = logging.getLogger(__name__)

ALIENVAULT_API_KEY = "81d2e210cd9b895d396f5fd2beef77eb4e66d924aeb8aff5d478fd9b9088dbec"
HEADERS = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}

SUSPICIOUS_KEYWORDS = ["login", "secure", "update", "verify", "account", "banking", "auth", "signin", "password", "credential", "billing", "support", "service", "admin"]

def extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except Exception:
        return url

def query_otx(indicator, indicator_type="domain"):
    # Fetches general, passive_dns, url_list, malware
    base_url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}"
    results = {
        "general": {},
        "passive_dns": [],
        "url_list": [],
        "malware": []
    }
    
    try:
        # General (Reputation, WHOIS info)
        r = requests.get(f"{base_url}/general", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            results["general"] = r.json()
            
        # Passive DNS
        r = requests.get(f"{base_url}/passive_dns", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            results["passive_dns"] = r.json().get('passive_dns', [])[:10]
            
        # URL List
        r = requests.get(f"{base_url}/url_list", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            results["url_list"] = r.json().get('url_list', [])[:10]
            
        # Malware
        r = requests.get(f"{base_url}/malware", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            results["malware"] = r.json().get('data', [])[:5]
            
    except Exception as e:
        logger.error(f"OTX query failed for {indicator}: {e}")
        
    return results

def query_misp(indicator):
    # Simulated MISP Query
    # In a real environment, this would use PyMISP or requests to a MISP instance.
    # We will simulate finding an IoC if the indicator contains suspicious patterns or has a bad TLD
    bad_tlds = [".xyz", ".top", ".pw", ".cc", ".club"]
    is_ioc = False
    reasons = []
    
    if any(indicator.endswith(tld) for tld in bad_tlds):
        is_ioc = True
        reasons.append(f"MISP IoC Match: Indicator has high-risk TLD")
        
    if any(kw in indicator.lower() for kw in SUSPICIOUS_KEYWORDS):
        if '-' in indicator:
            is_ioc = True
            reasons.append(f"MISP IoC Match: Indicator matches known phishing patterns")
            
    return {"is_ioc": is_ioc, "events": reasons}

def analyze_asset(asset, asset_type="domain", is_input=False):
    score = 0
    reasons = []
    
    # 1. Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in asset.lower()]
    if found_keywords:
        score += len(found_keywords) * 15
        reasons.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
        
    # Domain similarity (typosquatting simulation - dashes and multiple subdomains)
    if asset_type == "domain" or asset_type == "hostname":
        if '-' in asset:
            score += 15
            reasons.append("Domain contains hyphens (common in typosquatting)")
        if asset.count('.') > 2:
            score += 10
            reasons.append("Multiple subdomains detected")
            
    # 2. Query OTX
    otx_data = query_otx(asset, asset_type)
    pulses = otx_data.get("general", {}).get("pulse_info", {}).get("count", 0)
    if pulses > 0:
        score += min(40, pulses * 10)
        reasons.append(f"AlienVault OTX: Found in {pulses} pulses")
        
    if len(otx_data.get("malware", [])) > 0:
        score += 30
        reasons.append("AlienVault OTX: Associated malware found")
        
    whois_date = otx_data.get("general", {}).get("whois", "")
    if whois_date and "Created" in whois_date: # Simplified age check
        reasons.append("WHOIS data present")
        
    # 3. Query MISP
    misp_data = query_misp(asset)
    if misp_data["is_ioc"]:
        score += 35
        reasons.extend(misp_data["events"])
        
    return {
        "asset": asset,
        "score": min(100, score),
        "reasons": reasons,
        "otx_data": otx_data
    }

def run_anti_phishing_scan(scan_id):
    try:
        scan = AntiPhishingScan.objects.get(id=scan_id)
    except AntiPhishingScan.DoesNotExist:
        return
        
    scan.status = 'running'
    scan.save()
    
    url = scan.url
    domain = extract_domain(url)
    
    # 4. Analyze Input URL/Domain
    input_analysis = analyze_asset(domain, "domain", is_input=True)
    input_score = input_analysis["score"]
    all_reasons = [f"[Input Target] {r}" for r in input_analysis["reasons"]]
    
    if input_score > 70:
        classification = "Malicious"
    elif input_score >= 40:
        classification = "Suspicious"
    else:
        classification = "Safe"
        
    # 5. Extract Related Assets from OTX
    related_assets = set()
    otx = input_analysis["otx_data"]
    
    for pdns in otx.get("passive_dns", []):
        ip = pdns.get("address")
        if ip:
            related_assets.add(("IPv4", ip))
        host = pdns.get("hostname")
        if host and host != domain:
            related_assets.add(("hostname", host))
            
    for u in otx.get("url_list", []):
        r_url = u.get("url")
        if r_url:
            r_domain = extract_domain(r_url)
            if r_domain and r_domain != domain:
                related_assets.add(("domain", r_domain))
                
    related_assets = list(related_assets)[:5] # Limit to 5 to avoid infinite/long loops
    
    related_assets_score_total = 0
    analyzed_assets_count = 0
    
    for asset_type, asset_val in related_assets:
        res = analyze_asset(asset_val, asset_type)
        if res["score"] > 0:
            related_assets_score_total += res["score"]
            analyzed_assets_count += 1
            all_reasons.append(f"[Related {asset_type} {asset_val}] Risk Score {res['score']}: {', '.join(res['reasons'])}")
            
    avg_related_score = (related_assets_score_total / analyzed_assets_count) if analyzed_assets_count > 0 else 0
    
    # 6. Calculate Overall Ecosystem Score
    ecosystem_score = int((input_score * 0.7) + (avg_related_score * 0.3))
    
    if ecosystem_score >= 60:
        ecosystem_classification = "Phishing/Malicious"
    elif ecosystem_score >= 30:
        ecosystem_classification = "Suspicious"
    else:
        ecosystem_classification = "Safe"
        
    # Update scan object
    scan.risk_score = input_score
    scan.classification = classification
    scan.ecosystem_score = ecosystem_score
    scan.ecosystem_classification = ecosystem_classification
    scan.related_assets_found = len(related_assets)
    scan.reasons = all_reasons
    
    # Save OTX stuff to old fields to avoid breaking old UI parts
    scan.alienvault_pulse_count = otx.get("general", {}).get("pulse_info", {}).get("count", 0)
    scan.alienvault_reputation = otx
    
    scan.status = 'completed'
    scan.completed_at = timezone.now()
    scan.save()
