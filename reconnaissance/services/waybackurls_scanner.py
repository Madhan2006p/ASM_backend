from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
)


WAYBACKURLS_CANDIDATES = (
    r"C:\Users\samyu\go\bin\waybackurls.exe",
    r"C:\tools\waybackurls\waybackurls.exe",
)


def run_waybackurls(target):
    executable = resolve_executable(
        "waybackurls",
        env_var="WAYBACKURLS_PATH",
        candidates=WAYBACKURLS_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_urls": 0,
                "urls": [],
                "error": "waybackurls executable was not found on this system",
            },
        }

    execution = run_command(
        [executable, target],
        timeout=120,
    )

    raw_output = combine_output(execution["stdout"], execution["stderr"])
    urls = parse_waybackurls(execution["stdout"])
    parsed_output = {
        "total_urls": len(urls),
        "urls": urls,
        "execution_time": execution.get("execution_time"),
    }

    return {
        "raw_output": raw_output,
        "parsed_output": add_execution_error(parsed_output, execution),
    }


def parse_waybackurls(output):
    urls = dedupe_preserve_order(
        line.strip()
        for line in output.splitlines()
        if line.strip()
    )

    return [{"url": url} for url in urls]
