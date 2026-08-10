import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from .command_utils import (
    add_execution_error,
    combine_output,
    resolve_executable,
    run_command,
)

logger = logging.getLogger(__name__)

ARJUN_CANDIDATES = (
    r"C:\Users\samyu\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts\arjun.exe",
    r"C:\Python311\Scripts\arjun.exe",
    r"C:\Python312\Scripts\arjun.exe",
)


def run_arjun(target, method="GET", auth_header=None, auth_cookie=None):
    """
    Runs Arjun parameter discovery on a target and returns the discovered parameters.
    """
    if isinstance(target, list):
        target = target[0] if target else ""

    target = target.strip()
    if not target:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_parameters": 0,
                "parameters": [],
                "error": "No target provided for Arjun scan",
            },
        }

    executable = resolve_executable(
        "arjun",
        env_var="ARJUN_PATH",
        candidates=ARJUN_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_parameters": 0,
                "parameters": [],
                "error": "arjun executable was not found on this system",
            },
        }

    # Normalize to full URL
    if target.startswith("http://") or target.startswith("https://"):
        target_url = target
    else:
        target_url = f"https://{target}"

    tmpdir = tempfile.mkdtemp(prefix="arjun_")
    output_file = Path(tmpdir) / "report.json"

    command = [
        executable,
        "-u", target_url,
        "-oT", str(output_file),
    ]

    if method:
        command.extend(["-m", method])
    if auth_header:
        command.extend(["-H", auth_header])
    if auth_cookie:
        command.extend(["-c", auth_cookie])

    try:
        execution = run_command(command, timeout=300)
        raw_output = combine_output(execution["stdout"], execution["stderr"])

        params = []
        if output_file.exists():
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Parse Arjun results
                params_list = data.get(target_url, {}).get('params', [])
                if not params_list:
                    for url_key in data:
                        entry = data[url_key]
                        if isinstance(entry, dict) and 'params' in entry:
                            params_list = entry['params']
                            break

                for param in params_list:
                    param_name = param if isinstance(param, str) else param.get('name', str(param))
                    params.append(param_name)
            except Exception as e:
                logger.error("Failed to parse Arjun output: %s", e)

        parsed_output = {
            "total_parameters": len(params),
            "parameters": params,
            "execution_time": execution.get("execution_time"),
        }

        return {
            "raw_output": raw_output,
            "parsed_output": add_execution_error(parsed_output, execution),
        }

    except Exception as e:
        logger.exception("Arjun execution failed: %s", e)
        return {
            "raw_output": "",
            "parsed_output": {
                "total_parameters": 0,
                "parameters": [],
                "error": str(e),
            },
        }
