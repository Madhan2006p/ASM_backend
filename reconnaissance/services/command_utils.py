import glob
import os
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse


def resolve_executable(name, *, env_var=None, candidates=None):
    env_path = os.environ.get(env_var) if env_var else None

    if env_path and Path(os.path.expandvars(env_path)).exists():
        return os.path.expandvars(env_path)

    path_command = shutil.which(name)

    if path_command:
        return path_command

    for candidate in candidates or ():
        expanded_candidate = os.path.expandvars(candidate) if candidate else None

        if not expanded_candidate:
            continue

        matches = glob.glob(expanded_candidate)

        if matches:
            return str(matches[0])

        if Path(expanded_candidate).exists():
            return str(expanded_candidate)

    return None


def run_command(command, *, input_text=None, timeout=120):
    start = time.monotonic()

    try:
        completed = subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        elapsed = round(time.monotonic() - start, 3)

        return {
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "returncode": completed.returncode,
            "error": None,
            "execution_time": elapsed,
        }

    except FileNotFoundError:
        elapsed = round(time.monotonic() - start, 3)
        executable = command[0] if command else "command"

        return {
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": f"{executable} was not found on this system",
            "execution_time": elapsed,
        }

    except subprocess.TimeoutExpired:
        elapsed = round(time.monotonic() - start, 3)
        executable = command[0] if command else "command"

        return {
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": f"{executable} timed out after {timeout} seconds",
            "execution_time": elapsed,
        }

    except Exception as exc:
        elapsed = round(time.monotonic() - start, 3)
        executable = command[0] if command else "command"

        return {
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": f"{executable} failed: {exc}",
            "execution_time": elapsed,
        }


def combine_output(stdout, stderr):
    stdout = stdout or ""
    stderr = stderr or ""

    if stdout and stderr:
        return f"{stdout.rstrip()}\n\n[stderr]\n{stderr.strip()}"

    return stdout or stderr or ""


def add_execution_error(parsed_output, execution_result):
    if execution_result.get("error"):
        parsed_output["error"] = execution_result["error"]
        return parsed_output

    if execution_result.get("returncode") not in (None, 0):
        stderr = (execution_result.get("stderr") or "").strip()
        parsed_output["error"] = stderr or (
            f"Command exited with code {execution_result['returncode']}"
        )

    return parsed_output


@contextmanager
def temporary_file(*, suffix=".txt"):
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    temp_path = Path(handle.name)
    handle.close()

    try:
        yield temp_path
    finally:
        temp_path.unlink(missing_ok=True)


def read_file(path):
    file_path = Path(path)

    if not file_path.exists():
        return ""

    return file_path.read_text(encoding="utf-8", errors="ignore")


def write_lines(path, lines):
    Path(path).write_text(
        "\n".join(item for item in lines if item),
        encoding="utf-8",
    )


def dedupe_preserve_order(items):
    seen = set()
    unique_items = []

    for item in items:
        if item and item not in seen:
            seen.add(item)
            unique_items.append(item)

    return unique_items


def normalize_target(target):
    value = (target or "").strip()

    if not value:
        return ""

    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or parsed.netloc
    else:
        host = value.split("/")[0]

    host = (host or "").rstrip(".")
    return host.lower()


def extract_hostnames(values):
    hostnames = []

    for value in values or []:
        candidate = (value or "").strip()

        if not candidate:
            continue

        if "://" in candidate:
            parsed = urlparse(candidate)
            hostname = parsed.hostname
        else:
            parsed = urlparse(f"//{candidate}")
            hostname = parsed.hostname or candidate.split("/")[0]

        hostname = (hostname or "").rstrip(".").lower()

        if hostname:
            hostnames.append(hostname)

    return dedupe_preserve_order(hostnames)


def empty_collection_result(total_key, list_key, *, error=None):
    parsed_output = {
        total_key: 0,
        list_key: [],
        "execution_time": None,
    }

    if error:
        parsed_output["error"] = error

    return {
        "raw_output": "",
        "parsed_output": parsed_output,
    }
