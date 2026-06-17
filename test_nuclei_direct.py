import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from attacksurface.services import run_nuclei
print("Running nuclei on brokencrystals.com")
results = run_nuclei(["https://brokencrystals.com"], http_timeout=5)
print(f"Nuclei found {len(results)} vulnerabilities.")
for v in results:
    print(f"- {v.get('name')} ({v.get('severity')}) @ {v.get('target')} [ID: {v.get('template_id')}]")
