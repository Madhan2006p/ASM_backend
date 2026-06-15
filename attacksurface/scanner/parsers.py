import json
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_output):
    """Parse nmap XML output and return structured results.

    Returns list of dicts with: address, hostname, hostnames list, ports list.
    Each port dict: port, protocol, service, product, version.
    """
    results = []
    if not xml_output or not xml_output.strip():
        return results
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.warning("nmap XML parse error: %s", e)
        return results

    for host in root.findall(".//host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        address = addr_el.get("addr", "")
        addr_type = addr_el.get("addrtype", "")
        hostname = address
        hostnames_list = []
        hostname_els = host.findall(".//hostname")
        for hn in hostname_els:
            name = hn.get("name", "")
            if name:
                hostnames_list.append(name)
                hostname = name

        ports_list = []
        for port_el in host.findall(".//port"):
            port_id = port_el.get("portid", "")
            protocol = port_el.get("protocol", "")
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            try:
                port_num = int(port_id)
            except ValueError:
                continue
            ports_list.append({
                "port": port_num,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version,
            })

        results.append({
            "address": address,
            "addrtype": addr_type,
            "hostname": hostname,
            "hostnames": hostnames_list,
            "ports": sorted(ports_list, key=lambda x: x["port"]),
        })
    return results
