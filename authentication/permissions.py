from rest_framework import permissions


def get_user_organization(user):
    """Get the active organization for a user via their first membership."""
    membership = user.memberships.select_related("organization").first()
    if membership:
        return membership.organization, membership.role
    return None, None


class IsAuthenticatedAndOrgMember(permissions.BasePermission):
    """
    Ensures the user is authenticated AND has an organization membership.
    This should be the default for most views.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        # Superusers bypass org membership check
        if request.user.is_superuser:
            request.user_org = None
            request.user_org_role = "admin"
            return True
        org, role = get_user_organization(request.user)
        if org is None:
            return False
        # Attach org info to request for downstream use
        request.user_org = org
        request.user_org_role = role
        return True


class IsOrgAdmin(permissions.BasePermission):
    """
    Only allow users with 'admin' role in their organization.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        # Superusers bypass admin role check
        if request.user.is_superuser:
            request.user_org = None
            request.user_org_role = "admin"
            return True
        org, role = get_user_organization(request.user)
        if role != "admin":
            return False
        request.user_org = org
        request.user_org_role = role
        return True


class IsOrgAdminOrMember(permissions.BasePermission):
    """
    Allow users with 'admin' or 'member' role (deny 'viewer').
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        # Superusers bypass role check
        if request.user.is_superuser:
            request.user_org = None
            request.user_org_role = "admin"
            return True
        org, role = get_user_organization(request.user)
        if role not in ("admin", "member"):
            return False
        request.user_org = org
        request.user_org_role = role
        return True


# ─── Module-Level Permission Constants ────────────────────────────────────────

# Define module permission identifiers for granular access control
MODULE_PERMISSIONS = {
    "dashboard": "Can view dashboard",
    "subdomains": "Can view subdomains",
    "endpoints": "Can view endpoints",
    "open_ports": "Can view open ports",
    "directories": "Can view directories",
    "technologies": "Can view technologies",
    "vulnerabilities": "Can view vulnerabilities",
    "ssl_certificates": "Can view SSL certificates",
    "email_security": "Can view email security",
    "scan_history": "Can view scan history",
    "trigger_scan": "Can trigger scans",
    "manage_domains": "Can manage monitored domains",
    "marketplace": "Can access marketplace",
    "settings": "Can access settings",
    "manage_users": "Can manage users",
    "reconnaissance": "Can access reconnaissance tools",
    "apk_scanner": "Can use APK scanner",
    "fuzzing": "Can use fuzzing tools",
    "surface_web": "Can access Surface Web Monitoring",
    "brand_monitoring": "Can access Brand Monitoring & Anti-Malware",
}

# Role-to-permission mapping
# Admin: everything
# Member: most features except user management
# Viewer: read-only access to core modules
ROLE_PERMISSIONS = {
    "admin": set(MODULE_PERMISSIONS.keys()),
    "member": {
        "dashboard",
        "subdomains",
        "endpoints",
        "open_ports",
        "directories",
        "technologies",
        "vulnerabilities",
        "ssl_certificates",
        "email_security",
        "scan_history",
        "trigger_scan",
        "manage_domains",
        "marketplace",
        "settings",
        "reconnaissance",
        "apk_scanner",
        "fuzzing",
        "surface_web",
        "brand_monitoring",
    },
    "viewer": {
        "dashboard",
        "subdomains",
        "endpoints",
        "open_ports",
        "directories",
        "technologies",
        "vulnerabilities",
        "ssl_certificates",
        "email_security",
        "scan_history",
        "settings",
        "surface_web",
        "brand_monitoring",
    },
}


def get_user_org_id(request):
    """Get org_id from the authenticated user's membership.

    Can be overridden by admins via query param for cross-org operations.
    """
    # Allow query param override for admins
    query_org = request.query_params.get("org_id")
    if query_org and getattr(request, "user_org_role", None) == "admin":
        return query_org
    # Default: use the user's own organization
    org = getattr(request, "user_org", None)
    if org is not None:
        return org.org_id
    # Last resort: try user's actual membership
    if hasattr(request, "user") and request.user.is_authenticated and request.user.pk:
        org, _ = get_user_organization(request.user)
        if org:
            return org.org_id
    return "1"


def get_user_org_id_from_data(request):
    """Get org_id from POST data, falling back to user's org."""
    data_org = request.data.get("org_id")
    if data_org and getattr(request, "user_org_role", None) == "admin":
        return data_org
    return get_user_org_id(request)


# Feature number to module mapping (for feature-based access control)
FEATURE_MODULE_MAP = {
    "1": "subdomains",
    "2": "endpoints",
    "3": "open_ports",
    "4": "directories",
    "5": "technologies",
    "6": "vulnerabilities",
    "7": "ssl_certificates",
    "8": "email_security",
    "9": "scan_history",
    "10": "surface_web",
}


def user_has_module_permission(user, module_name):
    """Check if a user has permission for a given module based on their org role."""
    if not user or not user.is_authenticated:
        return False
    org, role = get_user_organization(user)
    if role is None:
        return False
    allowed = ROLE_PERMISSIONS.get(role, set())
    return module_name in allowed


def user_has_feature(user, module_name):
    """Check if a user has a specific feature unlocked by module name.
    
    If the user's features field is empty, all features are considered unlocked.
    """
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    profile = getattr(user, "asm_profile", None)
    if not profile or not profile.features:
        # Empty features = all unlocked
        return True
    feature_ids = [f.strip() for f in profile.features.split(",") if f.strip()]
    if not feature_ids:
        return True
    # Find which feature number corresponds to this module
    feature_id = None
    for fid, mod in FEATURE_MODULE_MAP.items():
        if mod == module_name:
            feature_id = fid
            break
    if feature_id is None:
        # No feature lock for this module
        return True
    return feature_id in feature_ids


class HasModulePermission(permissions.BasePermission):
    """
    Check module-level permission based on the view's `required_module` attribute.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        # Superusers have access to all modules
        if request.user.is_superuser:
            request.user_org = None
            request.user_org_role = "admin"
            return True
        module_name = getattr(view, "required_module", None)
        if module_name is None:
            # No module restriction — still require basic auth + org
            org, role = get_user_organization(request.user)
            if org is None:
                return False
            request.user_org = org
            request.user_org_role = role
            return True

        org, role = get_user_organization(request.user)
        if role is None:
            return False
        allowed = ROLE_PERMISSIONS.get(role, set())
        if module_name not in allowed:
            return False
        request.user_org = org
        request.user_org_role = role
        return True
