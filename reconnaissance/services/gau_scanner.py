from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
)


GAU_CANDIDATES = (
    r"C:\tools\gau\gau.exe",
    r"C:\Users\samyu\go\bin\gau.exe",
)


def run_gau(target):
    executable = resolve_executable(
        "gau",
        env_var="GAU_PATH",
        candidates=GAU_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_endpoints": 0,
                "endpoints": [],
                "error": "gau executable was not found on this system",
            },
        }

    execution = run_command(
        [
            executable,
            target,
        ],
        timeout=120,
    )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    endpoints = parse_gau(execution["stdout"])
    parsed_output = {
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
    }

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_gau(output):
    urls = dedupe_preserve_order(
        line.strip()
        for line in output.splitlines()
    )

    return [
        {"url": url}
        for url in urls
    ]
