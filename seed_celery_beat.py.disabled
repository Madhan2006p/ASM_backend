import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule
from django.utils import timezone

def seed_automation():
    print("Setting up automated scan intervals and schedules...")

    # 1. Create standard intervals
    every_15_mins, _ = IntervalSchedule.objects.get_or_create(
        every=15,
        period=IntervalSchedule.MINUTES
    )
    every_hour, _ = IntervalSchedule.objects.get_or_create(
        every=1,
        period=IntervalSchedule.HOURS
    )
    every_day, _ = IntervalSchedule.objects.get_or_create(
        every=24,
        period=IntervalSchedule.HOURS
    )
    print("Interval schedules registered.")

    # 2. Create standard crontabs (e.g., daily at midnight)
    midnight_cron, _ = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='0',
        day_of_week='*',
        day_of_month='*',
        month_of_year='*',
        timezone='Asia/Kolkata'
    )
    print("Crontab schedules registered.")

    # 3. Register automated Tasks to run on schedule
    # Automated Scans Queue Worker Task
    PeriodicTask.objects.get_or_create(
        name="Automated API Endpoint Discovery & Scan Scheduler (Every Day)",
        defaults={
            'task': 'scans.tasks.run_dirsearch',  # Trigger scan task
            'interval': every_day,
            'args': '[1]',  # Run on target ID 1
            'start_time': timezone.now()
        }
    )

    PeriodicTask.objects.get_or_create(
        name="Automated Arjun Parameter Fuzzing Processor (Every 15 Mins)",
        defaults={
            'task': 'fuzzing.tasks.run_arjun',  # Trigger fuzzing queue task
            'interval': every_15_mins,
            'args': '[1]',  # Run on queue ID 1
            'start_time': timezone.now()
        }
    )

    print("All automated periodic tasks successfully set up inside Celery Beat database!")

if __name__ == '__main__':
    seed_automation()
