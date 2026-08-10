import os, sys, logging, traceback
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import django
django.setup()

# Make all logger output visible on the terminal
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stdout,
)

from attacksurface.models import AttackSurfaceScan
from attacksurface.services import run_full_scan

scan = AttackSurfaceScan.objects.create(target='uit.ac.in', org_id='1', status='pending')
print(f"### Starting scan id={scan.id} for uit.ac.in")
try:
    run_full_scan(scan)
    scan.refresh_from_db()
    print(f"### FINAL status={scan.status} progress={scan.progress} vuln_phase={scan.vuln_scan_phase} vuln_done={scan.vulnerabilities_done}")
except Exception as e:
    print("### run_full_scan raised:", e)
    traceback.print_exc()
