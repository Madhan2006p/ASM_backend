from celery import shared_task
from django.utils import timezone

from .models import AttackSurfaceScan, MonitoredDomain
from .services import run_full_scan


@shared_task
def run_scheduled_domain_scans():
    now = timezone.localtime()
    today = now.date()
    started = []

    morning_candidates = MonitoredDomain.objects.filter(
        morning_enabled=True, morning_time=now.time(),
    ).exclude(last_morning_scan_at__date=today)

    night_candidates = MonitoredDomain.objects.filter(
        night_enabled=True, night_time=now.time(),
    ).exclude(last_night_scan_at__date=today)

    for item in morning_candidates:
        slot = "morning"
        scan = AttackSurfaceScan.objects.create(
            target=item.domain, org_id=item.org_id, status="pending",
        )
        run_full_scan(scan)
        item.last_morning_scan_at = timezone.now()
        item.save(update_fields=["last_morning_scan_at", "updated_at"])
        started.append({"domain": item.domain, "scan_id": scan.id, "slot": slot})

    for item in night_candidates:
        slot = "night"
        scan = AttackSurfaceScan.objects.create(
            target=item.domain, org_id=item.org_id, status="pending",
        )
        run_full_scan(scan)
        item.last_night_scan_at = timezone.now()
        item.save(update_fields=["last_night_scan_at", "updated_at"])
        started.append({"domain": item.domain, "scan_id": scan.id, "slot": slot})

    return {"started": started}
