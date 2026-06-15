from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
    temporary_file,
    write_lines,
)


HTTPX_CANDIDATES = (
    r"C:\Users\samyu\go\bin\httpx.exe",
    r"C:\tools\httpx\httpx.exe",
)


def run_httpx(subdomains):
    unique_subdomains = dedupe_preserve_order(
        item.strip()
        for item in subdomains or []
    )

    if not unique_subdomains:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_live_hosts": 0,
                "live_hosts": [],
            },
        }

    executable = resolve_executable(
        "httpx",
        env_var="HTTPX_PATH",
        candidates=HTTPX_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_live_hosts": 0,
                "live_hosts": [],
                "error": "httpx executable was not found on this system",
            },
        }

    with temporary_file(suffix=".txt") as input_file:
        write_lines(input_file, unique_subdomains)

        execution = run_command(
            [
                executable,
                "-l",
                str(input_file),
                "-silent",
            ],
            timeout=240,
        )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    parsed_hosts = parse_httpx(execution["stdout"])
    parsed_output = {
        "total_live_hosts": len(parsed_hosts),
        "live_hosts": parsed_hosts,
    }

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_httpx(output):
    live_hosts = dedupe_preserve_order(
        line.strip()
        for line in output.splitlines()
    )

    return [
        {"url": url}
        for url in live_hosts
    ]
