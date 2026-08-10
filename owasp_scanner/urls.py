"""
OWASP Scanner - URL Routing
============================
API routes for OWASP scanner:
  - POST /api/owasp-scanner/start/
  - GET  /api/owasp-scanner/sessions/
  - GET  /api/owasp-scanner/sessions/<uuid>/
  - GET  /api/owasp-scanner/sessions/<uuid>/status/
  - POST /api/owasp-scanner/sessions/<uuid>/cancel/
  - GET  /api/owasp-scanner/sessions/<uuid>/findings/
  - GET  /api/owasp-scanner/sessions/<uuid>/report/
  - GET  /api/owasp-scanner/sessions/<uuid>/assets/
  - GET  /api/owasp-scanner/sessions/<uuid>/logs/
  - GET  /api/owasp-scanner/findings/<uuid>/
  - POST /api/owasp-scanner/findings/<uuid>/false-positive/
  - POST /api/owasp-scanner/findings/<uuid>/verify/
  - GET  /api/owasp-scanner/stats/
"""
from django.urls import path
from . import views

app_name = 'owasp_scanner'

urlpatterns = [
    # Scan session endpoints
    path('start/', views.StartScanView.as_view(), name='start_scan'),
    path('sessions/', views.ScanSessionListView.as_view(), name='session_list'),
    path('sessions/<uuid:id>/', views.ScanSessionDetailView.as_view(), name='session_detail'),
    path('sessions/<uuid:session_id>/status/', views.ScanStatusView.as_view(), name='scan_status'),
    path('sessions/<uuid:session_id>/cancel/', views.CancelScanView.as_view(), name='cancel_scan'),
    path('sessions/<uuid:session_id>/findings/', views.FindingsListView.as_view(), name='session_findings'),
    path('sessions/<uuid:session_id>/report/', views.ScanReportView.as_view(), name='session_report'),
    path('sessions/<uuid:session_id>/assets/', views.AssetsListView.as_view(), name='session_assets'),
    path('sessions/<uuid:session_id>/logs/', views.ScanLogsView.as_view(), name='session_logs'),

    # Finding management endpoints
    path('findings/<uuid:id>/', views.FindingDetailView.as_view(), name='finding_detail'),
    path('findings/<uuid:finding_id>/false-positive/', views.MarkFalsePositiveView.as_view(), name='mark_false_positive'),
    path('findings/<uuid:finding_id>/verify/', views.VerifyFindingView.as_view(), name='verify_finding'),

    # Overall stats
    path('stats/', views.scanner_stats, name='scanner_stats'),
]
