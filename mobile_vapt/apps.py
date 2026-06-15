import logging
from django.apps import AppConfig

logger = logging.getLogger(__name__)


class MobileVaptConfig(AppConfig):
    name = 'mobile_vapt'

    def ready(self):
        """
        Called once by Django when the application is fully loaded.
        Auto-starts the MobSF Docker container (via docker-py).
        Catches all errors so a Docker failure never blocks Django boot.
        """
        try:
            from mobile_vapt.docker_manager import ensure_mobsf_running
            logger.info("[MobSF Docker] Checking / starting MobSF container …")
            ensure_mobsf_running()
        except Exception as exc:
            logger.error(f"[MobSF Docker] Auto-start failed (Django will still run): {exc}")
