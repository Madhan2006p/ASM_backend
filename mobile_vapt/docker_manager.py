"""
docker_manager.py
-----------------
Manages the MobSF Docker container lifecycle automatically.
Called from mobile_vapt/apps.py → ready() so it runs once when Django starts.

Flow:
  1. Connect to local Docker daemon.
  2. Look for a container with the configured name or image.
  3. If found and stopped  → start it.
  4. If not found at all   → run a fresh container from the image.
  5. Wait (up to 60 s) until MobSF responds on its HTTP port.
  6. Log every step clearly so the developer can follow along.
"""

import logging
import time

import requests as _requests
from django.conf import settings

logger = logging.getLogger(__name__)

# ── tuneable constants ──────────────────────────────────────────────────────
MOBSF_IMAGE         = getattr(settings, 'MOBSF_IMAGE',
                               'opensecurity/mobile-security-framework-mobsf:latest')
MOBSF_CONTAINER_NAME = getattr(settings, 'MOBSF_CONTAINER_NAME', 'mobsf_auto')
MOBSF_HOST_PORT     = getattr(settings, 'MOBSF_HOST_PORT', 8000)
MOBSF_API_KEY       = getattr(settings, 'MOBSF_API_KEY', '')
HEALTH_TIMEOUT      = 300   # seconds to wait for MobSF to become ready
HEALTH_INTERVAL     = 3     # seconds between health-check retries


def _get_docker_client():
    """Return a connected docker.DockerClient, or None if Docker is unavailable."""
    try:
        import docker
        client = docker.from_env()
        client.ping()          # raises if Docker daemon is not running
        return client
    except Exception as exc:
        logger.warning(f"[MobSF Docker] Cannot connect to Docker daemon: {exc}")
        return None


def _find_mobsf_container(client):
    """
    Return the first container that matches by name OR by image prefix.
    Checks both running and stopped containers.
    """
    # 1. exact name match (our managed container)
    try:
        return client.containers.get(MOBSF_CONTAINER_NAME)
    except Exception:
        pass

    # 2. look for any container with the MobSF image (e.g. the one user started manually)
    for container in client.containers.list(all=True):
        tags = container.image.tags or []
        if any(MOBSF_IMAGE.split(':')[0] in t for t in tags):
            logger.info(f"[MobSF Docker] Found existing container '{container.name}' with MobSF image.")
            return container

    return None


def _wait_for_mobsf(timeout: int = HEALTH_TIMEOUT) -> bool:
    """Poll MobSF root URL until it responds 200 or timeout is exceeded."""
    url = f"http://127.0.0.1:{MOBSF_HOST_PORT}/"
    headers = {'Authorization': MOBSF_API_KEY}
    deadline = time.time() + timeout
    attempt = 0

    logger.info(f"[MobSF Docker] Waiting for MobSF to be ready at {url} (timeout={timeout}s) …")
    while time.time() < deadline:
        attempt += 1
        try:
            resp = _requests.get(url, headers=headers, timeout=4)
            if resp.status_code == 200:
                logger.info(f"[MobSF Docker] MobSF is ready ✓ (attempt {attempt})")
                return True
        except Exception:
            pass
        time.sleep(HEALTH_INTERVAL)

    logger.error(f"[MobSF Docker] MobSF did NOT become ready within {timeout}s.")
    return False


def ensure_mobsf_running():
    """
    Main entry-point.  Called from apps.ready().
    Ensures the MobSF container is running and healthy before Django
    finishes starting up.
    """
    client = _get_docker_client()
    if client is None:
        logger.error("[MobSF Docker] Docker is unavailable – MobSF will NOT be started automatically.")
        return

    container = _find_mobsf_container(client)

    if container is None:
        # ── No container at all: create and start a new one ─────────────────
        logger.info(f"[MobSF Docker] No MobSF container found. Pulling image '{MOBSF_IMAGE}' and starting …")
        try:
            container = client.containers.run(
                image=MOBSF_IMAGE,
                name=MOBSF_CONTAINER_NAME,
                ports={f'8000/tcp': MOBSF_HOST_PORT},
                environment={'MOBSF_API_KEY': MOBSF_API_KEY},
                detach=True,
                restart_policy={"Name": "unless-stopped"},
            )
            logger.info(f"[MobSF Docker] Container '{container.name}' created and started (id={container.short_id}).")
        except Exception as exc:
            logger.error(f"[MobSF Docker] Failed to create/start MobSF container: {exc}")
            return

    else:
        status = container.status          # 'running', 'exited', 'paused', …
        logger.info(f"[MobSF Docker] Found container '{container.name}' (status={status}).")

        if status in ('exited', 'created', 'paused', 'dead'):
            logger.info(f"[MobSF Docker] Starting container '{container.name}' …")
            try:
                container.start()
                logger.info(f"[MobSF Docker] Container '{container.name}' started successfully.")
            except Exception as exc:
                logger.error(f"[MobSF Docker] Could not start container: {exc}")
                return

        elif status == 'running':
            logger.info(f"[MobSF Docker] Container '{container.name}' is already running.")

        else:
            logger.warning(f"[MobSF Docker] Container is in unexpected state '{status}' – attempting start anyway.")
            try:
                container.start()
            except Exception as exc:
                logger.error(f"[MobSF Docker] Could not start container: {exc}")
                return

    # ── Wait for MobSF HTTP to become available ──────────────────────────────
    _wait_for_mobsf()


def stop_mobsf():
    """
    Gracefully stop the MobSF container after scanning completes.
    Called from the background scan thread in views.py.
    """
    client = _get_docker_client()
    if client is None:
        logger.warning("[MobSF Docker] Cannot connect to Docker – skipping stop.")
        return

    container = _find_mobsf_container(client)
    if container is None:
        logger.info("[MobSF Docker] No MobSF container found to stop.")
        return

    if container.status == 'running':
        logger.info(f"[MobSF Docker] Stopping container '{container.name}' …")
        try:
            container.stop(timeout=10)
            logger.info(f"[MobSF Docker] Container '{container.name}' stopped.")
        except Exception as exc:
            logger.error(f"[MobSF Docker] Failed to stop container: {exc}")
    else:
        logger.info(f"[MobSF Docker] Container '{container.name}' is already stopped (status={container.status}).")
