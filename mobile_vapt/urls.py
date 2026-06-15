from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.FileUploadView.as_view(), name='mobile-upload'),
    path('scan-status/<int:pk>/', views.ScanStatusView.as_view(), name='scan-status'),
    path('findings/<int:pk>/', views.ScanFindingsView.as_view(), name='scan-findings'),
    path('findings/', views.AllFindingsView.as_view(), name='all-findings'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('history/', views.ScanHistoryView.as_view(), name='scan-history'),
    path('scan-detail/<int:pk>/', views.ScanDetailView.as_view(), name='scan-detail'),
    path('delete-scan/<int:pk>/', views.DeleteScanView.as_view(), name='delete-scan'),
    path('clear-all/', views.ClearAllScansView.as_view(), name='clear-all'),
]
