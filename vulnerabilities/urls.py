from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import VulnerabilityViewSet

router = DefaultRouter()
router.register(r'', VulnerabilityViewSet, basename='vulnerability')

urlpatterns = [
    path('', include(router.urls)),
]
