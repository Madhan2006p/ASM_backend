from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanViewSet, SSLResultViewSet, MonitorScheduleViewSet, DetectionResultViewSet

router = DefaultRouter()
router.register(r'', ScanViewSet, basename='scan')

urlpatterns = [
    path('ssl-results/', SSLResultViewSet.as_view({'get': 'list', 'head': 'list'}), name='ssl-result-list'),
    path('ssl-results/<int:pk>/', SSLResultViewSet.as_view({'get': 'retrieve', 'head': 'retrieve'}), name='ssl-result-detail'),
    path('monitors/', MonitorScheduleViewSet.as_view({'get': 'list', 'post': 'create'}), name='monitor-list'),
    path('monitors/<int:pk>/', MonitorScheduleViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='monitor-detail'),
    path('detections/', DetectionResultViewSet.as_view({'get': 'list'}), name='detection-list'),
    path('detections/<int:pk>/', DetectionResultViewSet.as_view({'get': 'retrieve'}), name='detection-detail'),
    path('detections/<int:pk>/acknowledge/', DetectionResultViewSet.as_view({'post': 'acknowledge'}), name='detection-acknowledge'),
    path('', include(router.urls)),
]
