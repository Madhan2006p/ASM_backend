import logging
import os
import subprocess
import shutil
import sys
import tempfile
import time
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_tool(tool_name, env_var, candidates=None):
    """Resolve the full path of an external tool binary.

    Checks:
    1. Environment variable override
    2. shutil.which() on PATH
    3. P Setting pip user scripts directory (Windows)
    4. Provided candidate paths
    """
    env_val = os.environ.get(env_var) if env_var else None
    if env_val and os.path.exists(env_val):
        return env_val
    resolved = shutil.which(tool_name)
    if resolved:
        return resolved
    if os.name == "nt":
        try:
            import sysconfig
            user_scripts = sysconfig.get_paths("nt_user").get("scripts")
            if user_scripts:
                exe = Path(user_scripts) / f"{tool_name}.exe"
                if exe.exists():
                    return str(exe)
        except Exception:
            pass
    if candidates:
        for c in candidates:
            if c and os.path.exists(c):
                return c
    return None


def run_cmd(cmd, timeout=120, input_data=None, env=None):
    """Run an external command with timeout, return structured output."""
    start = time.time()
    result = {"stdout": "", "stderr": "", "returncode": -1, "execution_time": 0}
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            env=env,
        )
        result["stdout"] = r.stdout
        result["stderr"] = r.stderr
        result["returncode"] = r.returncode
    except FileNotFoundError:
        result["stderr"] = f"Command not found: {cmd[0]}"
        logger.warning("Tool not found: %s", cmd[0])
    except subprocess.TimeoutExpired as e:
        result["stdout"] = (e.stdout or "")[:1000]
        result["stderr"] = (e.stderr or "")[:1000]
        result["returncode"] = -1
        logger.warning("Command timed out after %ss: %s", timeout, cmd[0])
    except Exception as e:
        result["stderr"] = str(e)
        logger.error("Command failed: %s: %s", cmd[0], e)
    result["execution_time"] = round(time.time() - start, 2)
    return result


def mark_phase(scan, phase_field, progress):
    """Mark a scan phase as complete and update progress."""
    setattr(scan, phase_field, True)
    scan.progress = progress
    scan.save(update_fields=[phase_field, "progress"])
    logger.info("Scan %s: phase %s done (progress=%d)", scan.id, phase_field, progress)
