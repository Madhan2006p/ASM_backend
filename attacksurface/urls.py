from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .internal_views import InternalNetworkScanViewSet, InternalAssetViewSet

router = DefaultRouter()
router.register(r'internal-scans', InternalNetworkScanViewSet, basename='internal-scan')
router.register(r'internal-assets', InternalAssetViewSet, basename='internal-asset')

from .views import (
    ClearDatabaseView,
    DirectoryListView,
    DomainQuickScanView,
    EmailSecurityListView,
    EndpointListView,
    FaradayFindingsView,
    FaradaySummaryView,
    MonitoredDomainListView,
    PortListView,
    SSLResultListView,
    ScanHistoryView,
    ScanListView,
    ScanStatusView,
    ScanTriggerView,
    AdminScanTriggerView,
    SendVulnerabilitiesToFaradayView,
    SubdomainListView,
    TechnologyListView,
    VulnerabilityListView,
    ToolsHealthView,
    ExecutiveDashboardSummaryView,
    ScanReportView,
)

urlpatterns = [
    path("executive-dashboard/", ExecutiveDashboardSummaryView.as_view(), name="attacksurface-executive-dashboard-summary"),
    path("subdomains/", SubdomainListView.as_view(), name="attack-surface-subdomains"),
    path("endpoints/", EndpointListView.as_view(), name="attack-surface-endpoints"),
    path("open-ports/", PortListView.as_view(), name="attack-surface-ports"),
    path("directories/", DirectoryListView.as_view(), name="attack-surface-directories"),
    path("technologies/", TechnologyListView.as_view(), name="attack-surface-technologies"),
    path("vulnerabilities/", VulnerabilityListView.as_view(), name="attack-surface-vulnerabilities"),
    path("ssl-certificates/", SSLResultListView.as_view(), name="attack-surface-ssl"),
    path("email-security/", EmailSecurityListView.as_view(), name="attack-surface-email"),
    path("scans/", ScanListView.as_view(), name="attack-surface-scans"),
    path("domains/", MonitoredDomainListView.as_view(), name="attack-surface-domains"),
    path("domains/quick-scan/", DomainQuickScanView.as_view(), name="attack-surface-domain-quick-scan"),
    path("scan/", ScanTriggerView.as_view(), name="attack-surface-scan-trigger"),
    path("admin-scan/", AdminScanTriggerView.as_view(), name="attack-surface-admin-scan-trigger"),
    path("scan/<int:id>/", ScanStatusView.as_view(), name="attack-surface-scan-status"),
    path("scan/<int:scan_id>/report/", ScanReportView.as_view(), name="attack-surface-scan-report"),
    path("scan-history/", ScanHistoryView.as_view(), name="attack-surface-scan-history"),
    path("tools-health/", ToolsHealthView.as_view(), name="attacksurface-tools-health"),
    path("clear-db/", ClearDatabaseView.as_view(), name="attacksurface-clear-db"),
    path("vulnerabilities/send-to-faraday/", SendVulnerabilitiesToFaradayView.as_view(), name="attacksurface-send-to-faraday"),
    path("faraday-findings/", FaradayFindingsView.as_view(), name="attacksurface-faraday-findings"),
    path("faraday-summary/", FaradaySummaryView.as_view(), name="attacksurface-faraday-summary"),
    path("", include(router.urls)),
]
