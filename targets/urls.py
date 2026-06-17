from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TargetViewSet, EndpointViewSet, AdminDomainListView, AdminDomainDetailView

router = DefaultRouter()
router.register(r'', TargetViewSet, basename='target')
router.register(r'endpoints', EndpointViewSet, basename='endpoint')

urlpatterns = [
    path('', include(router.urls)),
    # Admin: org-scoped domain management
    path('admin/organizations/<str:org_id>/domains/', AdminDomainListView.as_view(), name='admin-domains-list'),
    path('admin/organizations/<str:org_id>/domains/<int:domain_id>/', AdminDomainDetailView.as_view(), name='admin-domains-detail'),
]
