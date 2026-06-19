from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    SpiderfootScanViewSet,
    SpiderfootResultViewSet,
    SpiderfootStatsView,
)

router = DefaultRouter()
router.register(r'scans', SpiderfootScanViewSet, basename='spiderfoot-scan')
router.register(r'results', SpiderfootResultViewSet, basename='spiderfoot-result')

urlpatterns = [
    path('stats/', SpiderfootStatsView.as_view(), name='spiderfoot-stats'),
    path('', include(router.urls)),
]
