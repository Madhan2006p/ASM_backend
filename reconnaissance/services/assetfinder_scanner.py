from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
)


ASSETFINDER_CANDIDATES = (
    r"C:\Users\samyu\go\bin\assetfinder.exe",
    r"C:\tools\assetfinder\assetfinder.exe",
)


def run_assetfinder(target):
    executable = resolve_executable(
        "assetfinder",
        env_var="ASSETFINDER_PATH",
        candidates=ASSETFINDER_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_subdomains": 0,
                "subdomains": [],
                "error": "assetfinder executable was not found on this system",
                "execution_time": None,
            },
        }

    execution = run_command(
        [
            executable,
            "--subs-only",
            target,
        ],
        timeout=120,
    )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    parsed_subdomains = parse_assetfinder(execution["stdout"])
    parsed_output = {
        "total_subdomains": len(parsed_subdomains),
        "subdomains": parsed_subdomains,
        "execution_time": execution.get("execution_time"),
    }

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_assetfinder(output):
    subdomains = dedupe_preserve_order(
        line.strip()
        for line in output.splitlines()
    )

    return [
        {"subdomain": domain}
        for domain in subdomains
    ]
