import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from .command_utils import (
    add_execution_error,
    combine_output,
    dedupe_preserve_order,
    resolve_executable,
    run_command,
    temporary_file,
    write_lines,
)


NUCLEI_CANDIDATES = (
    r"C:\Users\samyu\Downloads\nuclei_3.8.0_windows_amd64\nuclei.exe",
    r"C:\Users\samyu\go\bin\nuclei.exe",
    r"C:\tools\nuclei\nuclei.exe",
)

# Tag groups executed in parallel for speed
TAG_GROUPS = [
    ["cve"],
    ["misconfiguration", "misconfig"],
    ["exposure", "default-login"],
]


def _run_batch(executable, targets, tags, severity, timeout):
    """Run one Nuclei subprocess for a specific tag group."""
    command = [
        executable,
        "-j",
        "-severity", severity,
        "-timeout", "5",
        "-retries", "1",
        "-rl", "80",
        "-bs", "20",
        "-c", "20",
        "-duc",
        "-ni",
        "-nc",
        "-tags", ",".join(tags),
    ]
    if len(targets) == 1:
        command.extend(["-u", targets[0]])
        execution = run_command(command, timeout=timeout)
    else:
        with temporary_file(suffix=".txt") as input_file:
            write_lines(input_file, targets)
            execution = run_command(
                command + ["-l", str(input_file)],
                timeout=timeout,
            )
    return parse_nuclei(execution["stdout"])


def run_nuclei(targets):
    normalized_targets = normalize_targets(targets)

    if not normalized_targets:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "error": "No scan targets were provided to nuclei",
            },
        }

    executable = resolve_executable(
        "nuclei",
        env_var="NUCLEI_PATH",
        candidates=NUCLEI_CANDIDATES,
    )

    if not executable:
        return {
            "raw_output": "",
            "parsed_output": {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "error": "nuclei executable was not found on this system",
            },
        }

    severity = "medium,high,critical"
    batch_timeout = max(180, 60 * len(normalized_targets))

    # Run tag groups in parallel for speed
    all_vulns = []
    with ThreadPoolExecutor(max_workers=min(len(TAG_GROUPS), 4)) as pool:
        futures = {
            pool.submit(_run_batch, executable, normalized_targets, group, severity, batch_timeout): group
            for group in TAG_GROUPS
        }
        for future in as_completed(futures):
            group = futures[future]
            try:
                all_vulns.extend(future.result())
            except Exception as exc:
                pass  # individual group failure is non-fatal

    # Deduplicate by (template_id, target)
    seen = set()
    deduped = []
    for v in all_vulns:
        key = (v.get("template_id"), v.get("target"))
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    raw_output = json.dumps(deduped)
    parsed_output = {
        "total_vulnerabilities": len(deduped),
        "vulnerabilities": deduped,
        "targets_scanned": normalized_targets,
    }

    return {
        "raw_output": raw_output,
        "parsed_output": parsed_output,
    }


def normalize_targets(targets):
    if isinstance(targets, str):
        values = [targets.strip()]
    else:
        values = [item.strip() for item in targets or [] if item]

    return dedupe_preserve_order(values)


def parse_nuclei(output):
    vulnerabilities = []

    for line in output.splitlines():
        payload = line.strip()

        if not payload:
            continue

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            continue

        vulnerabilities.append(
            {
                "template_id": data.get("template-id"),
                "name": data.get("info", {}).get("name"),
                "severity": data.get("info", {}).get("severity"),
                "type": data.get("type"),
                "protocol": data.get("protocol"),
                "target": data.get("matched-at") or data.get("url"),
                "host": data.get("host"),
                "timestamp": data.get("timestamp"),
            }
        )

    return vulnerabilities
