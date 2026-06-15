"""
faraday_manager.py
------------------
Auto-starts the Faraday pipeline (FastAPI + PostgreSQL) via docker-compose
when Django boots — called from findings/apps.py → ready().

Flow:
  1. Check if docker and docker-compose are available.
  2. Run `docker compose -f defectdojo_pipeline/docker-compose.yml up -d`
  3. Wait up to 60 s for the FastAPI service to respond on port 8001.
  4. Log every step so the developer can follow along.
"""

import logging
import os
import subprocess
import time

import requests as _requests

logger = logging.getLogger(__name__)

# Paths relative to the project root (one level above integrated_backend/)
PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
COMPOSE_FILE = os.path.join(PROJECT_ROOT, "defectdojo_pipeline", "docker-compose.yml")
FARADAY_PIPELINE_URL = "http://127.0.0.1:8001"
HEALTH_TIMEOUT = 120       # seconds to wait for Farady to become ready
HEALTH_INTERVAL = 4        # seconds between health-check retries


def _preflight_check() -> bool:
    """Return True if docker compose is available on this system."""
    for cmd in (
        ["docker", "compose", "version"],
        ["docker-compose", "version"],
    ):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def _is_pipeline_running() -> bool:
    """Quick ping to see if the pipeline is already accepting requests."""
    try:
        r = _requests.get(FARADAY_PIPELINE_URL, timeout=3)
        return r.status_code < 500
    except Exception:
        return False


def _wait_for_pipeline(timeout: int = HEALTH_TIMEOUT) -> bool:
    """Poll the pipeline until it responds or timeout is exceeded."""
    deadline = time.time() + timeout
    attempt = 0

    logger.info(
        "[Faraday Pipeline] Waiting for service to be ready at %s "
        "(timeout=%ds) …", FARADAY_PIPELINE_URL, timeout
    )
    while time.time() < deadline:
        attempt += 1
        if _is_pipeline_running():
            logger.info("[Faraday Pipeline] Ready ✓ (attempt %d)", attempt)
            return True
        time.sleep(HEALTH_INTERVAL)

    logger.error("[Faraday Pipeline] Did NOT become ready within %ds.", timeout)
    return False


def ensure_faraday_running():
    """
    Main entry-point.  Called from findings/apps.py ready().
    Ensures the Faraday pipeline (FastAPI + PostgreSQL) is running.
    """
    if _is_pipeline_running():
        logger.info("[Faraday Pipeline] Already running at %s", FARADAY_PIPELINE_URL)
        return

    if not _preflight_check():
        logger.error(
            "[Faraday Pipeline] docker / docker-compose not found on PATH. "
            "Faraday pipeline will NOT be started automatically."
        )
        return

    if not os.path.exists(COMPOSE_FILE):
        logger.error(
            "[Faraday Pipeline] Compose file not found at %s. "
            "Faraday pipeline will NOT be started.", COMPOSE_FILE
        )
        return

    logger.info(
        "[Faraday Pipeline] Starting services with docker-compose "
        "(file=%s) …", COMPOSE_FILE
    )

    try:
        result = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.path.dirname(COMPOSE_FILE),
        )
        if result.returncode != 0:
            stderr = result.stderr.strip() or "(no stderr)"
            logger.error(
                "[Faraday Pipeline] docker compose up failed "
                "(exit=%d): %s", result.returncode, stderr
            )
            return

        logger.info("[Faraday Pipeline] docker compose up succeeded ✓")
        # Show last line of stdout (typically contains container status)
        last_line = (result.stdout.strip() or "").splitlines()
        if last_line:
            logger.info("[Faraday Pipeline] %s", last_line[-1])

    except subprocess.TimeoutExpired:
        logger.error("[Faraday Pipeline] docker compose up timed out after 120s.")
        return
    except FileNotFoundError:
        logger.error("[Faraday Pipeline] 'docker' binary not found on PATH.")
        return
    except Exception as exc:
        logger.error("[Faraday Pipeline] Unexpected error starting services: %s", exc)
        return

    # Wait for health
    _wait_for_pipeline()
