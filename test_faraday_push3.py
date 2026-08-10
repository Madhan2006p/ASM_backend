import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
import django
sys.path.insert(0, '/home/madhan/Desktop/ASM-New/integrated_backend')
django.setup()

from attacksurface.models import VulnerabilityResult, AttackSurfaceScan
scan = AttackSurfaceScan.objects.last()
for v in VulnerabilityResult.objects.filter(scan=scan)[:5]:
    target = v.subdomain or v.domain or ""
    template_id = v.template_id or v.vulnerability_id or "unknown"
    source_tool = v.source_tool or "ASM"
    ext_id = f"asm-{source_tool}-{target}-{template_id}"
    print(ext_id)
