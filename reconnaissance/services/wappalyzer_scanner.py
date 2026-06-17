import json
import logging
import os
from urllib.parse import urlparse

from .command_utils import (
    dedupe_preserve_order,
    run_command,
    temporary_file,
    write_lines,
)

logger = logging.getLogger(__name__)

def run_wappalyzer(targets):
    """
    Detect web technologies using the Node.js Wappalyzer library.
    This properly executes JS in a headless browser to get accurate versions.
    """
    if isinstance(targets, str):
        targets = [targets]

    unique_targets = dedupe_preserve_order(
        item.strip()
        for item in targets or []
    )

    if not unique_targets:
        return _format_output({})

    script_path = os.path.join(os.path.dirname(__file__), "wappalyzer_runner.js")
    
    with temporary_file(suffix=".txt") as input_file:
        write_lines(input_file, unique_targets)
        
        command = ["node", script_path, str(input_file)]
        execution = run_command(command, timeout=max(240, 30 * len(unique_targets)))

    results = _parse_wappalyzer_node_output(execution["stdout"])
    return _format_output(results)


def _parse_wappalyzer_node_output(output):
    """Parses JSON output from the Node.js Wappalyzer runner."""
    try:
        # Find JSON boundaries since npm might print warnings
        start_idx = output.find('{')
        end_idx = output.rfind('}') + 1
        if start_idx == -1 or end_idx == 0:
            return {}
            
        data = json.loads(output[start_idx:end_idx])
        
        host_tech_map = {}
        for target_url, result in data.items():
            if "error" in result:
                logger.warning(f"Wappalyzer failed on {target_url}: {result['error']}")
                continue
                
            parsed = urlparse(target_url if target_url.startswith('http') else 'https://' + target_url)
            domain = parsed.hostname or target_url
            base_url = f"{parsed.scheme}://{domain}" if parsed.scheme else f"https://{domain}"
            
            if base_url not in host_tech_map:
                host_tech_map[base_url] = {"domain": domain, "url": base_url, "technologies": set()}
                
            for tech in result.get("technologies", []):
                name = tech.get("name", "")
                version = tech.get("version", "")
                if name:
                    formatted_tech = f"{name}/{version}" if version else name
                    host_tech_map[base_url]["technologies"].add(formatted_tech)
                    
        return host_tech_map
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode Wappalyzer JSON: {e}")
        return {}


def _format_output(host_tech_map):
    """Format the technology detection results into standard output format."""
    tech_counter = {}
    hosts = []

    for base_url, info in host_tech_map.items():
        info["technologies"] = sorted(list(info["technologies"]))
        for t in info["technologies"]:
            # Extract base name for counting
            base_name = t.split('/')[0] if '/' in t else t
            tech_counter[base_name] = tech_counter.get(base_name, 0) + 1
        hosts.append(info)

    parsed_output = {
        "total_detected": len(hosts),
        "hosts": hosts,
        "technologies_summary": dict(
            sorted(tech_counter.items(), key=lambda x: -x[1])
        ),
    }

    return {
        "raw_output": str(hosts),
        "parsed_output": parsed_output,
    }
