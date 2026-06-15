from django.urls import path
from .views import (
    RunScanView,
    ReconScanListView,
    ToolOutputListView,
    DiscoveredDomainListView,
    ReconEndpointListView,
    DNSQueryView,
    EmailSecurityView,
    APIInspectView,
    MethodScanView,
    CollectApiUrlsView,
)

urlpatterns = [
    path("run-scan/", RunScanView.as_view(), name="recon-run-scan"),
    path("dns-query/", DNSQueryView.as_view(), name="recon-dns-query"),
    path("email-security/", EmailSecurityView.as_view(), name="recon-email-security"),
    path("scans/", ReconScanListView.as_view(), name="recon-scans"),
    path("tool-outputs/", ToolOutputListView.as_view(), name="recon-tool-outputs"),
    path("domains/", DiscoveredDomainListView.as_view(), name="recon-domains"),
    path("endpoints/", ReconEndpointListView.as_view(), name="recon-endpoints"),
    path("inspect/", APIInspectView.as_view(), name="recon-inspect"),
    path("method-scan/", MethodScanView.as_view(), name="recon-method-scan"),
    path("collect-api-urls/", CollectApiUrlsView.as_view(), name="recon-collect-api"),
]
