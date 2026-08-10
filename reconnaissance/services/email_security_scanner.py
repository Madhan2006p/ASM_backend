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
        "smtp_hosts": [],
        "smtp_port_scan": {},
        "smtp_open_relay": {},
        "smtp_starttls": {},
    }

    try:
        import checkdmarc
        cd_res = checkdmarc.check_domains([domain])
        
        # Resolve cd_domain_res properly depending on format returned
        if isinstance(cd_res, list) and len(cd_res) > 0:
            cd_domain_res = cd_res[0]
        elif isinstance(cd_res, dict):
            cd_domain_res = cd_res.get(domain, cd_res)
        else:
            cd_domain_res = cd_res
            
        if isinstance(cd_domain_res, dict):
            # Parse SPF
            spf_data = cd_domain_res.get("spf", {})
            spf_record = spf_data.get("record")
            if spf_record:
                result["spf"] = [spf_record]
                result["root_txt"].append(spf_record)
            
            # Parse DMARC
            dmarc_data = cd_domain_res.get("dmarc", {})
            dmarc_record = dmarc_data.get("record")
            if dmarc_record:
                result["dmarc"] = [dmarc_record]
                result["root_txt"].append(dmarc_record)
                
            # Parse MX and STARTTLS
            mx_data = cd_domain_res.get("mx", {})
            hosts = mx_data.get("hosts") or []
            mx_records = []
            smtp_hosts = []
            starttls_supported = False
            
            for host in hosts:
                pref = host.get("preference", 10)
                hostname = host.get("hostname", "")
                if hostname:
                    mx_records.append(f"{pref} {hostname}")
                    smtp_hosts.append(hostname)
                if host.get("starttls") or host.get("tls"):
                    starttls_supported = True
            
            result["mx"] = mx_records
            result["smtp_hosts"] = smtp_hosts
            result["smtp_starttls"] = {
                "supported": starttls_supported,
                "checked": True,
            }
            
    except Exception as e:
        print(f"checkdmarc failed for {domain}: {e}")
        
    return result
