from django.http import JsonResponse
from django.urls import get_resolver

def api_root(request):
    urls = [
        ("admin/", "Django Admin"),
        ("api/auth/token/", "JWT Token Obtain"),
        ("api/auth/token/refresh/", "JWT Token Refresh"),
        ("api/auth/token/verify/", "JWT Token Verify"),
        ("api/auth/", "Authentication (register, profile)"),
        ("api/targets/", "Targets Management"),
        ("api/scans/", "Scans Management"),
        ("api/fuzzing/", "Fuzzing Results"),
        ("api/vulnerabilities/", "Vulnerabilities"),
        ("api/apk/", "APK Scanner"),
        ("api/recon/", "Reconnaissance (subdomains, DNS, email)"),
        ("api/recon/scans/", "Recon Scans List"),
        ("api/recon/domains/", "Discovered Domains"),
        ("api/recon/endpoints/", "Recon Endpoints"),
        ("api/attacksurface/", "Attack Surface Management"),
        ("api/attacksurface/subdomains/", "Attack Surface Subdomains"),
        ("api/attacksurface/endpoints/", "Attack Surface Endpoints"),
        ("api/attacksurface/open-ports/", "Open Ports"),
        ("api/attacksurface/directories/", "Directories"),
        ("api/attacksurface/vulnerabilities/", "Attack Surface Vulnerabilities"),
        ("api/attacksurface/ssl-certificates/", "SSL Certificates"),
        ("api/attacksurface/email-security/", "Email Security"),
        ("api/attacksurface/scans/", "Attack Surface Scans"),
        ("api/attacksurface/domains/", "Monitored Domains"),
    ]
    endpoints = [{"path": p, "description": d} for p, d in urls]
    return JsonResponse({
        "service": "ASM Attack Surface Management API",
        "version": "1.0",
        "endpoints": endpoints,
    })


# Error handlers
def handler400(request, exception=None):
    return JsonResponse({"error": "Bad request"}, status=400)


def handler403(request, exception=None):
    return JsonResponse({"error": "Permission denied"}, status=403)


def handler404(request, exception=None):
    return JsonResponse({"error": "Not found"}, status=404)


def handler500(request):
    return JsonResponse({"error": "Server error"}, status=500)
