from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    BrandMonitorTargetViewSet,
    VirusTotalReportViewSet,
    SuspiciousDomainReportViewSet,
    PhishingDomainReportViewSet,
    ImpersonatingScanViewSet,
    ImpersonatingAccountResultViewSet,
    AntiPhishingScanViewSet,
)

router = DefaultRouter()
router.register(r'targets', BrandMonitorTargetViewSet, basename='brand-target')
router.register(r'reports', VirusTotalReportViewSet, basename='brand-report')
router.register(r'suspicious-domains', SuspiciousDomainReportViewSet, basename='suspicious-domain')
router.register(r'phishing-domains', PhishingDomainReportViewSet, basename='phishing-domain')
router.register(r'impersonation-scans', ImpersonatingScanViewSet, basename='impersonation-scan')
router.register(r'impersonation-results', ImpersonatingAccountResultViewSet, basename='impersonation-result')
router.register(r'anti-phishing', AntiPhishingScanViewSet, basename='anti-phishing')

urlpatterns = [
    path('', include(router.urls)),
]
