from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import APKFileViewSet

router = DefaultRouter()
router.register(r'', APKFileViewSet, basename='apk')

urlpatterns = [
    path('', include(router.urls)),
]
