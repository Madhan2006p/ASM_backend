import json
import logging
import os
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def _compute_ssl_grade(cert, tls_version):
    """Compute an SSL grade (A+ through F) based on cert properties."""
    if not cert:
        return "F"
    score = 100
    tls_ver = (tls_version or "").upper()
    if "SSLv2" in tls_ver or "SSLv3" in tls_ver:
        score -= 50
    elif "TLSv1.0" in tls_ver or "TLSv1" == tls_ver.strip():
        score -= 30
    elif "TLSv1.1" in tls_ver:
        score -= 20
    elif "TLSv1.3" in tls_ver:
        score += 5
    try:
        nb = cert.get("notBefore", "")
        na = cert.get("notAfter", "")
        date_fmt = "%b %d %H:%M:%S %Y %Z"
        if nb and na:
            not_before = datetime.strptime(nb, date_fmt)
            not_after = datetime.strptime(na, date_fmt)
            now = datetime.utcnow()
            if now < not_before:
                score -= 40
            days_left = (not_after - now).days
            if days_left < 0:
                score -= 80
            elif days_left < 30:
                score -= 30
            elif days_left < 90:
                score -= 10
    except (ValueError, TypeError):
        pass
    sig_algo = (cert.get("signatureAlgorithm") or "").upper()
    if "MD5" in sig_algo or "SHA1" in sig_algo:
        score -= 30
    elif "SHA256" in sig_algo or "SHA384" in sig_algo or "SHA512" in sig_algo:
        score += 5
    subject_raw = cert.get("subject", [])
    cn = ""
    for part in subject_raw:
        if isinstance(part, tuple):
            for kv in part:
                if isinstance(kv, tuple) and len(kv) >= 2 and kv[0] == "commonName":
                    cn = kv[1]
        elif isinstance(part, list):
            for kv in part:
                if isinstance(kv, tuple) and len(kv) >= 2 and kv[0] == "commonName":
                    cn = kv[1]
    if cn.startswith("*."):
        score -= 5
    if score >= 95:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 65:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 30:
        return "D"
    else:
        return "F"


def _cert_issuer_str(issuer_parts):
    """Convert cert issuer tuple-of-tuples to a readable string."""
    pairs = []
    for part in issuer_parts:
        if isinstance(part, tuple):
            for kv in part:
                if isinstance(kv, tuple) and len(kv) >= 2:
                    pairs.append(f"{kv[0]}={kv[1]}")
        elif isinstance(part, list):
            for kv in part:
                if isinstance(kv, tuple) and len(kv) >= 2:
                    pairs.append(f"{kv[0]}={kv[1]}")
    return "; ".join(pairs) if pairs else str(issuer_parts)


def run_testssl(targets):
    """SSL/TLS certificate checker using testssl.sh."""
    if not targets:
        return []
    
    results = []
    # testssl.sh is heavily detailed but takes time, we'll scan all provided targets
    for raw_target in targets:
        host = raw_target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        
        # Temporary file for JSON output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            json_path = tmp_file.name

        try:
            logger.info("Running testssl.sh for %s", host)
            # testssl.sh options:
            # --fast: skip some slow tests
            # -U: skip auto updates
            # --quiet: suppress output
            # --jsonfile: dump to json
            cmd = ["testssl.sh", "--fast", "-U", "--quiet", "--jsonfile", json_path, host]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            
            # Default values
            grade = "F"
            issuer = ""
            ip_addr = host
            rdns = ""
            not_after = ""
            not_before = ""
            cipher_suite = ""
            is_trusted = False
            
            if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
                with open(json_path, 'r') as f:
                    try:
                        data = json.load(f)
                        # Depending on testssl.sh version, data might be list or dict
                        items = data if isinstance(data, list) else data.get('scanResult', [])
                        if isinstance(data, dict) and not isinstance(items, list):
                            # Flat struct inside scanResult?
                            items = [data]
                            
                        for item in items:
                            if "id" in item:
                                id_val = item.get("id", "")
                                finding = item.get("finding", "")
                                
                                if id_val == "grade":
                                    grade = finding.split(" ")[0] if finding else "F"
                                elif "cert_issuer" in id_val:
                                    issuer = finding
                                elif "cert_expiration" in id_val or id_val == "cert_notAfter":
                                    not_after = finding
                                elif "cert_notBefore" in id_val:
                                    not_before = finding
                                elif id_val == "cipher_suite":
                                    cipher_suite = finding
                                elif id_val == "scan_ip":
                                    ip_addr = finding
                                elif "trust" in id_val.lower():
                                    if "ok" in finding.lower() or "trusted" in finding.lower():
                                        is_trusted = True
                    except json.JSONDecodeError:
                        logger.error("Failed to parse testssl.sh output for %s", host)
                        
            # If grade still F and we found no issuer, maybe it failed
            if not issuer and grade == "F":
                results.append(_error_result(host, "No certificate or unreachable", ip_addr, rdns))
                continue
                
            results.append({
                "host": host,
                "ssl_grade": grade,
                "issuer": issuer,
                "ip": ip_addr,
                "rdns": rdns,
                "expiry_date": not_after,
                "purchase_date": not_before,
                "cipher_suite": cipher_suite,
                "is_trusted": is_trusted,
            })
            
        except subprocess.TimeoutExpired:
            logger.warning("testssl.sh timeout for %s", host)
            results.append(_error_result(host, "Timeout", host, ""))
        except Exception as e:
            logger.exception("testssl.sh failed for %s: %s", host, e)
            results.append(_error_result(host, str(e), host, ""))
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    return results

def _error_result(host, error_msg, ip, rdns):
    return {
        "host": host,
        "ssl_grade": "F",
        "issuer": f"Error: {error_msg}",
        "ip": ip,
        "rdns": rdns,
        "expiry_date": "",
        "purchase_date": "",
        "cipher_suite": "",
        "is_trusted": False,
    }
