from django.contrib import admin
from .models import ReconScan, ToolOutput, DiscoveredDomain, ReconEndpoint

admin.site.register(ReconScan)
admin.site.register(ToolOutput)
admin.site.register(DiscoveredDomain)
admin.site.register(ReconEndpoint)
