import os
import requests
import logging
from celery import shared_task
from .models import MobileScan

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"

@shared_task(bind=True)
def scan_apk_virustotal(self, scan_id):
    try:
        scan_obj = MobileScan.objects.get(id=scan_id)
    except MobileScan.DoesNotExist:
        logger.error(f"MobileScan {scan_id} not found.")
        return

    if not scan_obj.apk_file:
        logger.error(f"MobileScan {scan_id} has no APK file to scan.")
        return

    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        logger.error("VIRUSTOTAL_API_KEY is missing.")
        return

    file_path = scan_obj.apk_file.path
    if not os.path.exists(file_path):
        logger.error(f"File {file_path} not found.")
        return

    headers = {
        "x-apikey": key
    }

    logger.info(f"Uploading {file_path} to VirusTotal...")
    
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f, "application/vnd.android.package-archive")}
            response = requests.post(f"{VT_API_BASE}/files", headers=headers, files=files)
            response.raise_for_status()
            
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            if analysis_id:
                scan_obj.vt_scan_id = analysis_id
                scan_obj.status = 'vt_scanning'
                scan_obj.save(update_fields=['vt_scan_id', 'status'])
                logger.info(f"File uploaded successfully. Analysis ID: {analysis_id}")
                
                # Chain to check the analysis result later if needed, but for now we just record the ID.
                # In a real scenario we might poll or schedule a task to poll.
                # Let's poll immediately with backoff or just wait a bit.
                # A separate task can be scheduled to poll.
                from django.conf import settings
                if getattr(settings, 'CELERY_TASK_ALWAYS_EAGER', False):
                    import threading
                    import time
                    def delayed_start():
                        time.sleep(30)
                        poll_virustotal_analysis(scan_id, analysis_id)
                    threading.Thread(target=delayed_start, daemon=True).start()
                else:
                    poll_virustotal_analysis.apply_async(args=[scan_id, analysis_id], countdown=60)
            else:
                logger.error("No analysis ID returned from VirusTotal.")
    except Exception as e:
        logger.error(f"Failed to upload {file_path} to VirusTotal: {e}")

@shared_task(bind=True, max_retries=10)
def poll_virustotal_analysis(self, scan_id, analysis_id):
    try:
        scan_obj = MobileScan.objects.get(id=scan_id)
    except MobileScan.DoesNotExist:
        return

    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        return

    headers = {
        "x-apikey": key
    }

    try:
        response = requests.get(f"{VT_API_BASE}/analyses/{analysis_id}", headers=headers)
        response.raise_for_status()
        data = response.json().get("data", {})
        status = data.get("attributes", {}).get("status")
        
        if status == "queued" or status == "in-progress":
            from django.conf import settings
            if getattr(settings, 'CELERY_TASK_ALWAYS_EAGER', False):
                import threading
                import time
                def delayed_poll():
                    time.sleep(30)
                    poll_virustotal_analysis(scan_id, analysis_id)
                threading.Thread(target=delayed_poll, daemon=True).start()
                return
            else:
                raise self.retry(countdown=60)
        
        if status == "completed":
            stats = data.get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            
            scan_obj.score = f"{malicious} Malicious / {suspicious} Suspicious / {undetected} Undetected"
            scan_obj.status = "vt_completed"
            scan_obj.save(update_fields=['score', 'status'])
            logger.info(f"Scan {scan_id} completed: {scan_obj.score}")

    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking analysis {analysis_id}: {e}")
        raise self.retry(exc=e, countdown=60)
