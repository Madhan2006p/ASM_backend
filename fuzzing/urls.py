from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import FuzzingQueueViewSet, FuzzingResultViewSet

router = DefaultRouter()
router.register(r'queue', FuzzingQueueViewSet, basename='fuzzing-queue')
router.register(r'results', FuzzingResultViewSet, basename='fuzzing-result')

urlpatterns = [
    path('', include(router.urls)),
]
