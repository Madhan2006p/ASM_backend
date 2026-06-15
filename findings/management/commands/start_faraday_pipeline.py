"""
Management command to start the Faraday pipeline (FastAPI + PostgreSQL)
independently of Django's startup.

Usage:
    python manage.py start_faraday_pipeline
"""

import logging
from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Start the Faraday pipeline (FastAPI + PostgreSQL) via docker compose"

    def handle(self, *args, **options):
        from findings.faraday_manager import ensure_faraday_running

        self.stdout.write("Starting Faraday pipeline …")
        ensure_faraday_running()

        # Check if it's now running
        from findings.faraday_manager import _is_pipeline_running
        if _is_pipeline_running():
            self.stdout.write(self.style.SUCCESS("Faraday pipeline is running at http://127.0.0.1:8001"))
        else:
            self.stdout.write(self.style.WARNING("Faraday pipeline did not start. Check logs for details."))
