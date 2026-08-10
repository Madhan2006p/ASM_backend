"""Quick verification that A01 no longer flags admin paths that redirect to a login page."""
import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
sys.path.insert(0, ".")
import django

django.setup()

from owasp_scanner.detectors.a01_broken_access_control import detect_a01
from owasp_scanner.detectors.base import HTTPClient

host = "uit.ac.in"
base_urls = ["https://uit.ac.in"]

with HTTPClient() as http:
    findings = detect_a01(host, host, base_urls, http)

print("A01 findings for uit.ac.in:", len(findings))
for f in findings:
    print(" -", f["vulnerability_id"], "|", f["severity"], "|", f["finding"][:90])
print("DONE")
