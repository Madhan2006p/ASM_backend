from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
)


SUBFINDER_CANDIDATES = (
    r"C:\tools\subfinder\subfinder.exe",
    r"C:\Users\samyu\go\bin\subfinder.exe",
)


def run_subfinder(target):
    executable = resolve_executable(
        "subfinder",
        env_var="SUBFINDER_PATH",
        candidates=SUBFINDER_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_subdomains": 0,
                "subdomains": [],
                "error": "subfinder executable was not found on this system",
                "execution_time": None,
            },
        }

    execution = run_command(
        [
            executable,
            "-d",
            target,
            "-all",
            "-silent",
            "-active",
        ],
        timeout=120,
    )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    parsed_subdomains = parse_subfinder(execution["stdout"])
    parsed_output = {
        "total_subdomains": len(parsed_subdomains),
        "subdomains": parsed_subdomains,
        "execution_time": execution.get("execution_time"),
    }

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_subfinder(output):
    subdomains = dedupe_preserve_order(
        line.strip()
        for line in output.splitlines()
    )

    return [
        {"subdomain": domain}
        for domain in subdomains
    ]
