from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
)


NAABU_CANDIDATES = (
    r"C:\Users\samyu\go\bin\naabu.exe",
    r"C:\tools\naabu\naabu.exe",
)


def run_naabu(target):
    executable = resolve_executable(
        "naabu",
        env_var="NAABU_PATH",
        candidates=NAABU_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_open_ports": 0,
                "open_ports": [],
                "error": "naabu executable was not found on this system",
            },
        }

    execution = run_command(
        [
            executable,
            "-host",
            target,
            "-p",
            "-",
            "-rate",
            "5000",
            "-silent",
            "-verify",
        ],
        timeout=300,
    )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    parsed_ports = parse_naabu(execution["stdout"])
    parsed_output = {
        "total_open_ports": len(parsed_ports),
        "open_ports": parsed_ports,
    }

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_naabu(output):
    ports = []

    for entry in dedupe_preserve_order(
        line.strip()
        for line in output.splitlines()
    ):
        if ":" not in entry:
            continue

        host, port = entry.rsplit(":", 1)

        ports.append(
            {
                "host": host,
                "port": port,
                "state": "open",
            }
        )

    return ports
