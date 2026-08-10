import os, sys, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import django
django.setup()

from owasp_scanner.engine import run_owasp_top10_scan

domain = sys.argv[1] if len(sys.argv) > 1 else 'hackersinfotech.com'
start = time.time()
result = run_owasp_top10_scan(domain)
elapsed = round(time.time() - start, 1)

print('TOTAL FINDINGS:', result['total'], 'in', elapsed, 's', flush=True)
for c in result['categories']:
    if c['count'] > 0:
        sev = c['severities']
        print(f"  {c['id']} (rank {c['rank']}): {c['count']} findings | crit={sev['critical']} high={sev['high']} med={sev['medium']} low={sev['low']} info={sev['info']}", flush=True)
