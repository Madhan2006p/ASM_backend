import xml.etree.ElementTree as ET

from .command_utils import (
    add_execution_error,
    extract_hostnames,
    normalize_target,
    read_file,
    resolve_executable,
    run_command,
    temporary_file,
    write_lines,
)


NMAP_CANDIDATES = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


def run_nmap(
    targets,
    *,
    ports=None,
    top_ports=1000,
    scripts="default,vuln",
    syn_scan=True,
    service_detection=True,
    os_detection=True,
    timing=4,
    timeout=600,
):
    normalized_targets = normalize_targets(targets)

    if not normalized_targets:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_hosts": 0,
                "total_ports": 0,
                "hosts": [],
                "ports": [],
                "error": "No scan targets were provided to nmap",
            },
        }

    executable = resolve_executable(
        "nmap",
        env_var="NMAP_PATH",
        candidates=NMAP_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_hosts": 0,
                "total_ports": 0,
                "hosts": [],
                "ports": [],
                "error": "nmap executable was not found on this system",
            },
        }

    command = [executable]

    if syn_scan:
        command.append("-sS")

    if service_detection:
        command.append("-sV")

    if os_detection:
        command.append("-O")

    if ports:
        command.extend(["-p", str(ports)])
    elif top_ports:
        command.extend(["--top-ports", str(top_ports)])

    if timing:
        command.append(f"-T{timing}")

    if scripts:
        command.extend(["--script", scripts])

    with temporary_file(suffix=".xml") as xml_file:
        command.extend(["-oX", str(xml_file)])

        if len(normalized_targets) == 1:
            command.append(normalized_targets[0])
            execution = run_command(command, timeout=timeout)
        else:
            with temporary_file(suffix=".txt") as target_file:
                write_lines(target_file, normalized_targets)
                execution = run_command(
                    command + ["-iL", str(target_file)],
                    timeout=timeout,
                )

        raw_output = read_file(xml_file)

    parsed_nmap = parse_nmap(raw_output)
    parsed_output = {
        "total_hosts": len(parsed_nmap["hosts"]),
        "total_ports": len(parsed_nmap["ports"]),
        "hosts": parsed_nmap["hosts"],
        "ports": parsed_nmap["ports"],
        "targets_scanned": normalized_targets,
    }

    if execution.get("stderr") and not raw_output:
        raw_output = execution["stderr"]

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def normalize_targets(targets):
    if isinstance(targets, str):
        candidates = [normalize_target(targets)]
    else:
        candidates = extract_hostnames(targets)

    return [
        item
        for item in candidates
        if item
    ]


def parse_nmap(output):
    parsed_output = {
        "hosts": [],
        "ports": [],
    }

    if not output.strip():
        return parsed_output

    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return parsed_output

    for host_node in root.findall("host"):
        host_status_node = host_node.find("status")
        status = host_status_node.get("state") if host_status_node is not None else None

        address = None

        for address_node in host_node.findall("address"):
            if address_node.get("addrtype") in {"ipv4", "ipv6"}:
                address = address_node.get("addr")
                break

        if not address:
            first_address = host_node.find("address")
            address = first_address.get("addr") if first_address is not None else None

        hostname_node = host_node.find("./hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None

        os_matches = [
            os_match.get("name")
            for os_match in host_node.findall("./os/osmatch")
            if os_match.get("name")
        ]

        host_scripts = [
            {
                "id": script_node.get("id"),
                "output": script_node.get("output"),
            }
            for script_node in host_node.findall("./hostscript/script")
        ]

        host_summary = {
            "address": address,
            "hostname": hostname,
            "status": status,
            "os_matches": os_matches,
            "scripts": host_scripts,
            "ports": [],
        }

        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            port_scripts = [
                {
                    "id": script_node.get("id"),
                    "output": script_node.get("output"),
                }
                for script_node in port_node.findall("script")
            ]

            port_data = {
                "host": address,
                "hostname": hostname,
                "protocol": port_node.get("protocol"),
                "port": port_node.get("portid"),
                "state": state_node.get("state") if state_node is not None else None,
                "service": service_node.get("name") if service_node is not None else None,
                "product": service_node.get("product") if service_node is not None else None,
                "version": service_node.get("version") if service_node is not None else None,
                "extra_info": service_node.get("extrainfo") if service_node is not None else None,
                "scripts": port_scripts,
            }

            host_summary["ports"].append(port_data)
            parsed_output["ports"].append(port_data)

        parsed_output["hosts"].append(host_summary)

    return parsed_output
