from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    RepoEventViewSet,
    RepoScanViewSet,
    SurfaceMonitorConfigViewSet,
    GitHubRepositoryViewSet,
)

router = DefaultRouter()
router.register(r'configs', SurfaceMonitorConfigViewSet, basename='surface-config')
router.register(r'repos', GitHubRepositoryViewSet, basename='surface-repo')
router.register(r'scans', RepoScanViewSet, basename='surface-scan')
router.register(r'events', RepoEventViewSet, basename='surface-event')

urlpatterns = [
    path('', include(router.urls)),
]
