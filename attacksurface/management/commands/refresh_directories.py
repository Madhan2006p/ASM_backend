"""
Re-probe stored DirectoryResult rows with the current analysis engine and
refresh their classification.

Why this exists: results stored before the content-based engine (or before
redirect-following was added) may carry stale HTTP statuses — e.g. a 301
trailing-slash redirect was recorded while a browser sees the final 403.
This command re-validates every stored row so the module reflects reality
without requiring a full rescan.

Usage::

    python manage.py refresh_directories [--scan <id>] [--dry-run] [--workers N]
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)

BASELINE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class Command(BaseCommand):
    help = (
        "Re-probe stored DirectoryResult rows with the current analysis engine "
        "(redirects followed, content-based classification) and refresh status, "
        "category, risk and access status."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--scan", type=int, default=None,
            help="Only refresh rows belonging to this scan id",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Report what would change without writing to the database",
        )
        parser.add_argument(
            "--workers", type=int, default=10,
            help="Number of parallel probing workers (default 10)",
        )

    def _baseline_for(self, host, client):
        from attacksurface.scanner.directory_analyzer import normalized_body_hash
        from attacksurface.scanner.directory_scanner import _fetch

        for scheme in ("https", "http"):
            status, _headers, body = _fetch(client, f"{scheme}://{host}/")
            if status is not None and status < 500:
                return normalized_body_hash(body)
        return None

    def handle(self, *args, **opts):
        from attacksurface.models import DirectoryResult
        from attacksurface.scanner.directory_analyzer import analyze_response
        from attacksurface.scanner.directory_scanner import _fetch

        dry_run = opts["dry_run"]
        qs = DirectoryResult.objects.all()
        if opts["scan"]:
            qs = qs.filter(scan_id=opts["scan"])
        rows = list(qs)
        if not rows:
            self.stdout.write(self.style.WARNING("No directory rows to refresh."))
            return

        hosts = sorted({
            urlparse(r.url).hostname for r in rows
            if r.url and urlparse(r.url).hostname
        })

        # Precompute per-host baselines (sequential) so soft-404 detection is
        # consistent across all rows of the same host.
        baseline_map = {}
        with httpx.Client(
            headers=BASELINE_HEADERS, timeout=12, verify=False,
            follow_redirects=False,
        ) as client:
            for host in hosts:
                baseline_map[host] = self._baseline_for(host, client)

        def probe(row):
            host = urlparse(row.url).hostname
            try:
                with httpx.Client(
                    headers=BASELINE_HEADERS, timeout=12, verify=False,
                    follow_redirects=False,
                ) as client:
                    status, headers, body = _fetch(client, row.url)
                if status is None:
                    return row.id, "unreachable", None
                content_length = len(body)
                try:
                    header_length = int(headers.get("content-length", 0) or 0)
                    if header_length > 0:
                        content_length = header_length
                except (ValueError, TypeError):
                    pass
                analysis = analyze_response(
                    row.url, status, headers, body,
                    baseline_hash=baseline_map.get(host),
                    content_length=content_length,
                )
                updated = {
                    "status": status,
                    "content_type": analysis["content_type"],
                    "content_details": analysis["preview"],
                    "category": analysis["category"],
                    "risk": analysis["risk"],
                    "access_status": analysis["access_status"],
                    "is_sensitive": analysis["is_sensitive"],
                    "sensitive_matches": analysis["sensitive_matches"],
                    "title": analysis["title"],
                    # QuerySet.update() bypasses auto_now, so set it explicitly
                    "updated": timezone.now(),
                }
                return row.id, "ok", updated
            except Exception as exc:
                logger.warning("refresh failed for %s: %s", row.url, exc)
                return row.id, "error", None

        changed = 0
        errors = 0
        unreachable = 0
        with ThreadPoolExecutor(max_workers=opts["workers"]) as pool:
            futures = [pool.submit(probe, row) for row in rows]
            for fut in as_completed(futures):
                row_id, state, updated = fut.result()
                if state == "ok" and updated:
                    if not dry_run:
                        DirectoryResult.objects.filter(id=row_id).update(**updated)
                    changed += 1
                elif state == "unreachable":
                    unreachable += 1
                elif state == "error":
                    errors += 1

        self.stdout.write(
            f"Refreshed {len(rows)} rows: {changed} updated "
            f"({unreachable} unreachable, {errors} errors)"
            + (" [DRY RUN — nothing written]" if dry_run else "")
        )
