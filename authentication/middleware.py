import re

from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

from .models import Organization


class OrgAccessMiddleware(MiddlewareMixin):
    """
    Middleware that validates organization-scoped access for API requests.

    For requests containing an `org_id` parameter (query or body), this middleware
    verifies the authenticated user has a membership in that organization.
    If the org_id doesn't match the user's org, it returns a 403 response.

    Skip validation for:
    - Public endpoints (login, register, token refresh)
    - Admin endpoints (superuser access, admin dashboards)
    - Static/media files
    """

    # Paths that don't require org validation
    PUBLIC_PATHS = {
        "/api/auth/login/",
        "/api/auth/register/",
        "/api/auth/token/",
        "/api/auth/token/refresh/",
        "/api/auth/token/verify/",
    }

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Skip if user is not authenticated yet (will be caught by DRF permissions)
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return None

        # Skip for public paths
        path = request.path_info
        if any(path.startswith(p) for p in self.PUBLIC_PATHS):
            return None

        # Skip for admin, static, media
        if path.startswith("/admin/") or path.startswith("/static/") or path.startswith("/media/"):
            return None

        # Superusers bypass org validation
        if request.user.is_superuser:
            return None

        # Extract org_id from URL kwargs, query params, or POST body
        org_id = view_kwargs.get("org_id") or request.GET.get("org_id")
        if not org_id and request.method in ("POST", "PUT", "PATCH"):
            if request.content_type == "application/json":
                try:
                    import json
                    body = json.loads(request.body)
                    org_id = body.get("org_id")
                except (json.JSONDecodeError, OSError):
                    pass
            elif request.content_type and "form-urlencoded" in request.content_type:
                org_id = request.POST.get("org_id")

        if not org_id:
            return None  # No org_id specified — let the view handle it

        # Check if user has a membership in this organization
        has_access = request.user.memberships.filter(
            organization__org_id=org_id
        ).exists()

        if not has_access:
            return JsonResponse(
                {"error": "Invalid Organization", "detail": f"You do not have access to organization '{org_id}'."},
                status=403,
            )

        return None
