from django.contrib import admin

from .models import (
    AttackSurfaceScan,
    SubdomainResult,
    EndpointResult,
    PortResult,
    DirectoryResult,
    TechnologyResult,
    VulnerabilityResult,
    SSLResult,
    EmailSecurityResult,
)

admin.site.register(AttackSurfaceScan)
admin.site.register(SubdomainResult)
admin.site.register(EndpointResult)
admin.site.register(PortResult)
admin.site.register(DirectoryResult)
admin.site.register(TechnologyResult)
admin.site.register(VulnerabilityResult)
admin.site.register(SSLResult)
admin.site.register(EmailSecurityResult)
