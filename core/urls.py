from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from .views import api_root

urlpatterns = [
    path('', api_root, name='api-root'),
    path('admin/', admin.site.urls),

    # JWT Auth
    path('api/auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/auth/', include('authentication.urls')),

    # Core modules
    path('api/targets/', include('targets.urls')),
    path('api/scans/', include('scans.urls')),
    path('api/fuzzing/', include('fuzzing.urls')),
    path('api/vulnerabilities/', include('vulnerabilities.urls')),

    # APK Scanner
    path('api/apk/', include('apk_scanner.urls')),

    # Reconnaissance (subdomain discovery, DNS, email security)
    path('api/recon/', include('reconnaissance.urls')),

    # Attack Surface Management (frontend-facing endpoints)
    path('api/attacksurface/', include('attacksurface.urls')),

    # Surface Web Monitoring (GitHub repo discovery & secret scanning)
    path('api/surface-monitoring/', include('surface_monitoring.urls')),

    # Brand Monitoring & Anti-Malware (VirusTotal domain checks)
    path('api/brand-monitoring/', include('brand_monitoring.urls')),

    # Mobile VAPT
    path('api/mobile-vapt/', include('mobile_vapt.urls')),
    
    # Faraday Integration
    path('api/faraday/', include('findings.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Error handlers
handler400 = 'core.views.handler400'
handler403 = 'core.views.handler403'
handler404 = 'core.views.handler404'
handler500 = 'core.views.handler500'
