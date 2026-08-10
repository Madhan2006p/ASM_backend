import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from attacksurface.models import VulnerabilityResult
vulns = VulnerabilityResult.objects.filter(domain__icontains='brokencrystals.com')
print(f"Total vulns for brokencrystals.com in DB: {vulns.count()}")
for v in vulns:
    print(f"- {v.name} ({v.severity}) from {v.source_tool}")
