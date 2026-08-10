"""
OWASP Scanner - Celery Tasks
==============================
Asynchronous Celery tasks for running OWASP scans.
Integrates with the existing ASM Django/Celery infrastructure.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger('scanner.tasks')


def execute_scan_sync(session_id: str, target_url: str,
                      categories: Optional[List[str]] = None,
                      config_overrides: Optional[Dict] = None,
                      task_id: Optional[str] = None):
    """Synchronous execution wrapper for OWASP scan."""
    from .models import OWASPScanSession
    from .orchestrator import OWASPScanner, load_config

    session = None
    try:
        session = OWASPScanSession.objects.get(id=session_id)
        session.status = 'RUNNING'
        session.started_at = timezone.now()
        if task_id:
            session.celery_task_id = task_id
        session.current_phase = 'Initializing'
        session.save()

        # Load and merge config
        config = load_config()
        if session.scan_config:
            _deep_merge(config, session.scan_config)
        if config_overrides:
            _deep_merge(config, config_overrides)

        # Run the async scanner in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            scanner = OWASPScanner(
                target_url=target_url,
                session_id=session_id,
                django_target_id=session.target_id,
                config=config,
                categories=categories or [],
                progress_callback=_make_progress_callback(session_id),
            )
            report = loop.run_until_complete(scanner.run())
        finally:
            loop.close()

        # Update session with final status
        session.refresh_from_db()
        session.status = 'COMPLETED'
        session.completed_at = timezone.now()
        if session.started_at:
            session.duration_seconds = (session.completed_at - session.started_at).total_seconds()
        session.progress_percent = 100.0
        session.current_phase = 'Completed'
        session.save()

        logger.info('OWASP scan completed for %s: %d findings', target_url,
                    report.get('summary', {}).get('total_findings', 0))
        return report

    except OWASPScanSession.DoesNotExist:
        logger.error('OWASP scan session %s not found', session_id)
        raise
    except Exception as e:
        logger.error('OWASP scan failed for %s: %s', target_url, e, exc_info=True)
        if session:
            session.status = 'FAILED'
            session.error_message = str(e)[:2000]
            session.completed_at = timezone.now()
            session.save()
        raise


@shared_task(bind=True, name='owasp_scanner.tasks.run_owasp_scan')
def run_owasp_scan(self, session_id: str, target_url: str,
                   categories: Optional[List[str]] = None,
                   config_overrides: Optional[Dict] = None):
    return execute_scan_sync(session_id, target_url, categories, config_overrides, task_id=self.request.id)


def _make_progress_callback(session_id: str):
    """Create an async progress callback that updates the Django session."""
    from asgiref.sync import sync_to_async
    @sync_to_async
    def update_db(phase: str, percent: float):
        try:
            from .models import OWASPScanSession
            OWASPScanSession.objects.filter(id=session_id).update(
                current_phase=phase,
                progress_percent=round(percent, 1)
            )
        except Exception as e:
            logger.error('Progress update error: %s', e)
    return update_db


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base dict."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


@shared_task(name='owasp_scanner.tasks.run_owasp_scan_category')
def run_owasp_scan_category(session_id: str, category: str):
    """
    Run a scan for a single OWASP category only.
    Useful for targeted rescans.
    """
    from .models import OWASPScanSession
    session = OWASPScanSession.objects.get(id=session_id)
    return run_owasp_scan.delay(
        session_id=session_id,
        target_url=session.target_url,
        categories=[category]
    )


@shared_task(name='owasp_scanner.tasks.cleanup_old_sessions')
def cleanup_old_sessions(days: int = 30):
    """
    Periodic task to clean up old scan sessions and their findings.
    """
    from django.utils import timezone
    from datetime import timedelta
    from .models import OWASPScanSession

    cutoff = timezone.now() - timedelta(days=days)
    deleted = OWASPScanSession.objects.filter(
        created_at__lt=cutoff,
        status__in=['COMPLETED', 'FAILED', 'CANCELLED']
    ).delete()
    logger.info('Cleaned up %s old OWASP scan sessions', deleted)
    return deleted
