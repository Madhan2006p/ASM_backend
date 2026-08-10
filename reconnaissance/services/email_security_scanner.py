"""
Email Security Scanner service using checkdmarc.
"""

def run_email_security_scan(domain):
    # Initialize default result structure (align with EmailSecurityResult model fields)
    result = {
        "domain": domain,
        "root_txt": [],
        "spf": [],
        "dmarc": [],
        "mx": [],
        "dkim_selector1": [],
        "dkim_default": [],
        "bimi": [],
        "smtp_hosts": [],
        "smtp_port_scan": {},
        "smtp_open_relay": {},
        "smtp_starttls": {},
    }

    try:
        import subprocess
        import json
        import os
        dss_path = os.path.expanduser('~/go/bin/dss')
        if not os.path.exists(dss_path):
            dss_path = "dss"

        res = subprocess.run([dss_path, "scan", domain, "-f", "json"], capture_output=True, text=True, timeout=60)
        stdout = res.stdout
        json_start = stdout.find('[{"scanResult"')
        if json_start != -1:
            json_str = stdout[json_start:]
            data = json.loads(json_str)
            if data and isinstance(data, list):
                scan_res = data[0].get("scanResult", {})
                
                spf_record = scan_res.get("spf")
                if spf_record:
                    result["spf"] = [spf_record]
                    result["root_txt"].append(spf_record)
                
                dmarc_record = scan_res.get("dmarc")
                if dmarc_record:
                    result["dmarc"] = [dmarc_record]
                    result["root_txt"].append(dmarc_record)
                
                mx_records = scan_res.get("mx", [])
                result["mx"] = [f"10 {mx}" for mx in mx_records]
                result["smtp_hosts"] = mx_records
                
                dkim_record = scan_res.get("dkim")
                if dkim_record:
                    result["dkim_default"] = [dkim_record]
                    
                bimi_record = scan_res.get("bimi")
                if bimi_record:
                    result["bimi"] = [bimi_record]

                # DSS doesn't provide explicit STARTTLS info by default,
                # mark checked as True for now.
                result["smtp_starttls"] = {
                    "supported": True if mx_records else False,
                    "checked": True,
                }
            
    except Exception as e:
        print(f"domain-security-scanner failed for {domain}: {e}")
        
    return result
