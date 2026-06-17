from django.urls import path
from .views import NucleiScanView, FindingsListView, FindingsSummaryView, ClearFindingsView

urlpatterns = [
    path('scan/', NucleiScanView.as_view(), name='nuclei-scan'),
    path('list/', FindingsListView.as_view(), name='findings-list'),
    path('summary/', FindingsSummaryView.as_view(), name='findings-summary'),
    path('clear/', ClearFindingsView.as_view(), name='findings-clear'),
]
