import dns.resolver

from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
)
from .nmap_scanner import run_nmap


OPENSSL_CANDIDATES = (
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
)

DIG_CANDIDATES = (
    r"C:\tools\bind\dig.exe",
    r"%LOCALAPPDATA%\Microsoft\WinGet\Packages\ISC.Bind_*\dig.exe",
    r"C:\Program Files\Git\usr\bin\dig.exe",
)


def get_records(domain, record_type):
    dig_records = query_with_dig(domain, record_type)

    if dig_records is not None:
        return {
            "backend": "dig",
            "records": dig_records,
        }

    return {
        "backend": "dnspython",
        "records": query_with_dnspython(domain, record_type),
    }


def query_with_dig(domain, record_type):
    executable = resolve_executable(
        "dig",
        env_var="DIG_PATH",
        candidates=DIG_CANDIDATES,
    )

    if not executable:
        return None

    execution = run_command(
        [
            executable,
            "+short",
            record_type,
            domain,
        ],
        timeout=30,
    )

    if execution.get("error") or execution.get("returncode") not in (None, 0):
        return None

    return [
        line.strip()
        for line in execution["stdout"].splitlines()
        if line.strip()
    ]


def query_with_dnspython(domain, record_type):
    records = []

    try:
        answers = dns.resolver.resolve(domain, record_type)
    except Exception:
        return records

    for rdata in answers:
        records.append(str(rdata))

    return records


def run_email_security_scan(domain):
    root_txt = get_records(domain, "TXT")
    dmarc = get_records(f"_dmarc.{domain}", "TXT")
    mx = get_records(domain, "MX")
    dkim_selector1 = get_records(f"selector1._domainkey.{domain}", "TXT")
    dkim_default = get_records(f"default._domainkey.{domain}", "TXT")

    root_txt_records = root_txt["records"]
    mx_records = mx["records"]

    smtp_hosts = extract_smtp_hosts(domain, mx_records)
    smtp_target = smtp_hosts[0] if smtp_hosts else f"mail.{domain}"

    smtp_port_scan = run_nmap(
        smtp_hosts or [smtp_target],
        ports="25,465,587",
        top_ports=None,
        scripts=None,
        syn_scan=False,
        service_detection=False,
        os_detection=False,
        timing=None,
        timeout=300,
    )

    smtp_open_relay = run_nmap(
        [smtp_target],
        ports="25",
        top_ports=None,
        scripts="smtp-open-relay",
        syn_scan=False,
        service_detection=False,
        os_detection=False,
        timing=None,
        timeout=300,
    )

    smtp_starttls = run_smtp_starttls(smtp_target)

    return {
        "domain": domain,
        "dns_backend": choose_dns_backend(
            root_txt,
            dmarc,
            mx,
            dkim_selector1,
            dkim_default,
        ),
        "root_txt": root_txt_records,
        "spf": [
            record
            for record in root_txt_records
            if "v=spf1" in record.lower()
        ],
        "dmarc": dmarc["records"],
        "mx": mx_records,
        "dkim_selector1": dkim_selector1["records"],
        "dkim_default": dkim_default["records"],
        "smtp_hosts": smtp_hosts,
        "smtp_port_scan": smtp_port_scan["parsed_output"],
        "smtp_open_relay": smtp_open_relay["parsed_output"],
        "smtp_starttls": smtp_starttls["parsed_output"],
    }


def choose_dns_backend(*query_results):
    for query_result in query_results:
        if query_result["backend"] == "dig":
            return "dig"

    return "dnspython"


def extract_smtp_hosts(domain, mx_records):
    hosts = []

    for record in mx_records:
        parts = record.split()

        if not parts:
            continue

        hosts.append(parts[-1].rstrip("."))

    hosts.append(f"mail.{domain}")

    return dedupe_preserve_order(hosts)


def run_smtp_starttls(host):
    executable = resolve_executable(
        "openssl",
        env_var="OPENSSL_PATH",
        candidates=OPENSSL_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "host": host,
                "error": "openssl executable was not found on this system",
            },
        }

    execution = run_command(
        [
            executable,
            "s_client",
            "-starttls",
            "smtp",
            "-connect",
            f"{host}:25",
            "-servername",
            host,
        ],
        input_text="QUIT\n",
        timeout=60,
    )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    parsed_output = parse_smtp_starttls(raw_output)
    parsed_output["host"] = host

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_smtp_starttls(output):
    parsed_output = {
        "subject": None,
        "issuer": None,
        "protocol": None,
        "cipher": None,
        "start_date": None,
        "expire_date": None,
        "verify_return_code": None,
    }

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line.startswith("subject="):
            parsed_output["subject"] = line.split("subject=", 1)[1].strip()
        elif line.startswith("issuer="):
            parsed_output["issuer"] = line.split("issuer=", 1)[1].strip()
        elif line.startswith("Protocol"):
            parsed_output["protocol"] = line.split(":", 1)[1].strip()
        elif line.startswith("Cipher"):
            parsed_output["cipher"] = line.split(":", 1)[1].strip()
        elif line.startswith("start date:"):
            parsed_output["start_date"] = line.split(":", 1)[1].strip()
        elif line.startswith("expire date:"):
            parsed_output["expire_date"] = line.split(":", 1)[1].strip()
        elif line.startswith("Verify return code:"):
            parsed_output["verify_return_code"] = line.split(":", 1)[1].strip()

    return parsed_output
