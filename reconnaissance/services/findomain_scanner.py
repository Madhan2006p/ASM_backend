from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
)


FINDOMAIN_CANDIDATES = (
    r"C:\Users\samyu\go\bin\findomain.exe",
    r"C:\tools\findomain\findomain.exe",
)


def run_findomain(target):
    executable = resolve_executable(
        "findomain",
        env_var="FINDOMAIN_PATH",
        candidates=FINDOMAIN_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_subdomains": 0,
                "subdomains": [],
                "error": "findomain executable was not found on this system",
                "execution_time": None,
            },
        }

    execution = run_command(
        [
            executable,
            "-t",
            target,
        ],
        timeout=180,
    )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    parsed_subdomains = parse_findomain(execution["stdout"])
    parsed_output = {
        "total_subdomains": len(parsed_subdomains),
        "subdomains": parsed_subdomains,
        "execution_time": execution.get("execution_time"),
    }

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_findomain(output):
    subdomains = dedupe_preserve_order(
        line.strip()
        for line in output.splitlines()
    )

    return [
        {"subdomain": domain}
        for domain in subdomains
    ]
