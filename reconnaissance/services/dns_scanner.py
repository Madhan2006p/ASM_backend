import dns.resolver

def query_dns(domain):
    results = {
        "domain": domain,
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": []
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            for answer in answers:
                results[record_type].append(str(answer))

        except Exception:
            results[record_type] = []

    return results