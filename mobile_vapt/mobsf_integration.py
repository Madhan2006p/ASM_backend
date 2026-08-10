import os
import requests
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


class MobSFClient:
    def __init__(self):
        self.base_url = settings.MOBSF_URL
        self.api_key = settings.MOBSF_API_KEY
        self.headers = {
            'Authorization': self.api_key,
        }

    def upload_file(self, file_path):
        url = f"{self.base_url}/api/v1/upload"
        try:
            file_name = os.path.basename(file_path)  # Fix: works correctly on Windows
            with open(file_path, 'rb') as f:
                files = {'file': (file_name, f, 'application/octet-stream')}
                response = requests.post(url, files=files, headers=self.headers, timeout=(10, 300))
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"MobSF upload failed: {e}")
            return None

    def start_scan(self, scan_hash, scan_type='apk'):
        url = f"{self.base_url}/api/v1/scan"
        # MobSF expects: apk, ipa, zip, appx - map source names correctly
        type_map = {'android': 'apk', 'ios': 'ipa'}
        mobsf_type = type_map.get(scan_type, scan_type)
        data = {'hash': scan_hash, 'scan_type': mobsf_type}
        try:
            # /api/v1/scan is synchronous: it blocks until the full static analysis
            # finishes and then returns JSON. Large APKs can take 20+ minutes, so
            # allow a very generous read timeout to avoid spurious failures.
            response = requests.post(url, data=data, headers=self.headers, timeout=(10, 3600))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"MobSF scan failed: {e}")
            return None

    def get_report_json(self, scan_hash):
        url = f"{self.base_url}/api/v1/report_json"
        data = {'hash': scan_hash}
        try:
            response = requests.post(url, data=data, headers=self.headers, timeout=(10, 300))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"MobSF report fetch failed: {e}")
            return None

    def get_pdf_report(self, scan_hash):
        url = f"{self.base_url}/api/v1/download_pdf"
        data = {'hash': scan_hash}
        try:
            response = requests.post(url, data=data, headers=self.headers, timeout=(10, 300))
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            logger.error(f"MobSF PDF download failed: {e}")
            return None

    def check_health(self):
        # MobSF does not have /api/v1/health - check root page availability instead.
        # The root URL redirects (302) to the login page, so treat any 2xx/3xx
        # response as healthy; anything else (or a connection failure) is not.
        url = f"{self.base_url}/"
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            return 200 <= response.status_code < 400
        except requests.exceptions.RequestException:
            return False
