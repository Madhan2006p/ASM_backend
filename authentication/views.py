from django.contrib.auth import authenticate, get_user_model
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Organization, OrganizationMembership, UserDomain, UserProfile
from .permissions import IsOrgAdmin
from .serializers import (
    OrganizationMembershipSerializer,
    OrganizationSerializer,
    UserSerializer,
)

User = get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


def get_user_data(user):
    membership = (
        user.memberships.select_related("organization").first()
        if hasattr(user, "memberships") and user.pk
        else None
    )
    org_id = "1"
    org_name = "Default Org"
    role = "member"
    if membership:
        org_id = membership.organization.org_id
        org_name = membership.organization.name
        role = membership.role

    # Ensure UserProfile exists for feature support & domain admin fields
    profile = getattr(user, "asm_profile", None)
    if not profile:
        profile = UserProfile.objects.get_or_create(user=user)[0]

    # Parse features - comma-separated IDs, empty means all unlocked
    features = []
    if profile.features:
        features = [f.strip() for f in profile.features.split(",") if f.strip()]

    # Load admin-assigned domains the user is allowed to scan
    assigned_domains = list(
        UserDomain.objects.filter(user=user).values_list("domain__domain", flat=True)
    )

    return {
        "id": user.id,
        "name": user.get_full_name() or user.username,
        "email": user.email,
        "username": user.username,
        "phone_number": profile.phone_number if profile else "",
        "organization_id": org_id,
        "organization": org_name,
        "role": role,
        "features": features,
        "assigned_domains": assigned_domains,
    }


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        return Response(
            {
                "tokens": tokens,
                "user": get_user_data(user),
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email", "")
        password = request.data.get("password", "")
        username = request.data.get("username", "")

        if email:
            try:
                user_obj = User.objects.get(email=email)
                username = user_obj.username
            except User.DoesNotExist:
                pass

        user = authenticate(username=username, password=password)
        if not user:
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        tokens = get_tokens_for_user(user)
        return Response(
            {
                "tokens": tokens,
                "user": get_user_data(user),
            }
        )


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
        except Exception:
            pass
        return Response({"message": "Logged out successfully"})


class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(get_user_data(request.user))


class CheckAuthView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"authenticated": True, "user": get_user_data(request.user)})


# ─── Organization Management Views ────────────────────────────────────────────

class OrganizationListView(APIView):
    """List organizations for the current user and create new ones."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        organizations = Organization.objects.filter(
            memberships__user=request.user
        ).distinct()
        serializer = OrganizationSerializer(
            organizations, many=True, context={"request": request}
        )
        return Response(serializer.data)

    def post(self, request):
        name = request.data.get("name", "").strip()
        if not name:
            return Response(
                {"error": "Organization name is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        org = Organization.objects.create(
            name=name, org_id=name.lower().replace(" ", "-")[:50]
        )
        OrganizationMembership.objects.create(
            user=request.user, organization=org, role="admin"
        )
        serializer = OrganizationSerializer(org, context={"request": request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class OrganizationDetailView(APIView):
    """Get or update organization details (admin only)."""
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request, org_id):
        membership = request.user.memberships.filter(
            organization__org_id=org_id
        ).first()
        if not membership:
            return Response({"error": "Organization not found"}, status=404)
        serializer = OrganizationSerializer(
            membership.organization, context={"request": request}
        )
        return Response(serializer.data)

    def patch(self, request, org_id):
        membership = request.user.memberships.filter(
            organization__org_id=org_id, role="admin"
        ).first()
        if not membership:
            return Response({"error": "Not authorized"}, status=403)
        org = membership.organization
        name = request.data.get("name")
        if name:
            org.name = name.strip()
            org.save()
        serializer = OrganizationSerializer(org, context={"request": request})
        return Response(serializer.data)


class OrganizationMembersView(APIView):
    """List and manage organization members (admin only)."""
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request, org_id):
        membership = request.user.memberships.filter(
            organization__org_id=org_id, role="admin"
        ).first()
        if not membership:
            return Response({"error": "Not authorized"}, status=403)
        members = OrganizationMembership.objects.filter(
            organization=membership.organization
        ).select_related("user", "organization")
        serializer = OrganizationMembershipSerializer(members, many=True)
        return Response(serializer.data)

    def post(self, request, org_id):
        """Add a member to the organization."""
        membership = request.user.memberships.filter(
            organization__org_id=org_id, role="admin"
        ).first()
        if not membership:
            return Response({"error": "Not authorized"}, status=403)

        email = request.data.get("email", "")
        role = request.data.get("role", "member")
        if role not in ("admin", "member", "viewer"):
            role = "member"

        try:
            invited_user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "User with this email not found"}, status=404
            )

        _, created = OrganizationMembership.objects.get_or_create(
            user=invited_user,
            organization=membership.organization,
            defaults={"role": role},
        )
        if not created:
            return Response(
                {"error": "User is already a member"}, status=409
            )
        return Response({"message": "Member added successfully"}, status=201)

    def patch(self, request, org_id):
        """Update a member's role."""
        membership = request.user.memberships.filter(
            organization__org_id=org_id, role="admin"
        ).first()
        if not membership:
            return Response({"error": "Not authorized"}, status=403)

        member_id = request.data.get("member_id")
        new_role = request.data.get("role", "member")
        if new_role not in ("admin", "member", "viewer"):
            return Response({"error": "Invalid role"}, status=400)

        updated = OrganizationMembership.objects.filter(
            id=member_id, organization=membership.organization
        ).update(role=new_role)
        if not updated:
            return Response({"error": "Member not found"}, status=404)
        return Response({"message": "Role updated successfully"})

    def delete(self, request, org_id):
        """Remove a member from the organization."""
        membership = request.user.memberships.filter(
            organization__org_id=org_id, role="admin"
        ).first()
        if not membership:
            return Response({"error": "Not authorized"}, status=403)

        member_id = request.data.get("member_id")
        deleted, _ = OrganizationMembership.objects.filter(
            id=member_id, organization=membership.organization
        ).exclude(role="admin").delete()
        if not deleted:
            return Response({"error": "Member not found or cannot remove admin"}, status=404)
        return Response({"message": "Member removed successfully"})


# ─── Feature Management API ────────────────────────────────────────────────

# All available features with their IDs, names, and module keys
AVAILABLE_FEATURES = [
    {"id": "1", "name": "Subdomains", "module": "subdomains"},
    {"id": "2", "name": "Endpoints", "module": "endpoints"},
    {"id": "3", "name": "Open Ports", "module": "open_ports"},
    {"id": "4", "name": "Directories", "module": "directories"},
    {"id": "5", "name": "Technologies", "module": "technologies"},
    {"id": "6", "name": "Vulnerabilities", "module": "vulnerabilities"},
    {"id": "7", "name": "SSL Certificates", "module": "ssl_certificates"},
    {"id": "8", "name": "Email Security", "module": "email_security"},
    {"id": "9", "name": "Scan History", "module": "scan_history"},
    {"id": "10", "name": "Surface Web Monitoring", "module": "surface_web"},
]


class ListFeaturesView(APIView):
    """
    List all available features that can be given/taken from users.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(AVAILABLE_FEATURES)


class UserFeatureManagementView(APIView):
    """
    Manage features for a specific user (admin only).
    - GET: List the user's granted features
    - POST (give): Grant a feature to the user
    - POST (take): Revoke a feature from the user
    """
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request, user_id):
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        # Ensure the target user is in the same org as the admin
        if not request.user.is_superuser:
            admin_membership = request.user.memberships.filter(
                organization__memberships__user=target_user
            ).first()
            if not admin_membership:
                return Response({"error": "User is not in your organization"}, status=403)

        profile = getattr(target_user, "asm_profile", None)
        if not profile:
            profile = UserProfile.objects.get_or_create(user=target_user)[0]

        granted_features = []
        if profile.features:
            feature_ids = [f.strip() for f in profile.features.split(",") if f.strip()]
            for fid in feature_ids:
                match = next((f for f in AVAILABLE_FEATURES if f["id"] == fid), None)
                if match:
                    granted_features.append(match)

        return Response({
            "user_id": target_user.id,
            "username": target_user.username,
            "email": target_user.email,
            "granted_features": granted_features,
            "feature_ids": profile.features or "",
        })

    def post(self, request, user_id):
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        # Ensure same org
        if not request.user.is_superuser:
            admin_membership = request.user.memberships.filter(
                organization__memberships__user=target_user
            ).first()
            if not admin_membership:
                return Response({"error": "User is not in your organization"}, status=403)

        profile = getattr(target_user, "asm_profile", None)
        if not profile:
            profile = UserProfile.objects.get_or_create(user=target_user)[0]

        action = request.data.get("action", "")
        feature_id = request.data.get("feature_id", "")

        if not feature_id:
            return Response({"error": "feature_id is required"}, status=400)

        # Validate feature_id
        valid = next((f for f in AVAILABLE_FEATURES if f["id"] == feature_id), None)
        if not valid:
            return Response({"error": f"Invalid feature_id: {feature_id}. Must be 1-10."}, status=400)

        # Parse current features
        current_features = set()
        if profile.features:
            current_features = set(f.strip() for f in profile.features.split(",") if f.strip())

        if action == "give":
            current_features.add(feature_id)
            message = f'Feature "{valid["name"]}" granted to {target_user.username}'
        elif action == "take":
            current_features.discard(feature_id)
            message = f'Feature "{valid["name"]}" revoked from {target_user.username}'
        else:
            return Response({"error": "action must be 'give' or 'take'"}, status=400)

        profile.features = ",".join(sorted(current_features, key=int))
        profile.save(update_fields=["features"])

        return Response({
            "message": message,
            "user_id": target_user.id,
            "username": target_user.username,
            "feature_ids": profile.features,
        })


# ─── Admin: Create User Accounts Directly ──────────────────────────────────

class AdminCreateUserView(APIView):
    """
    Admin-only endpoint to create user accounts with direct password assignment.
    Allows superusers and org admins to create users and assign them to orgs.
    """
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request):
        username = request.data.get("username", "").strip()
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")
        org_id = request.data.get("org_id", "")
        role = request.data.get("role", "member")
        full_name = request.data.get("full_name", "").strip()
        phone_number = request.data.get("phone_number", request.data.get("phone", "")).strip()

        if not username or not email or not password:
            return Response(
                {"error": "username, email, and password are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if role not in ("admin", "member", "viewer"):
            role = "member"

        # Validate org_id — the admin must be admin of this org OR be superuser
        if request.user.is_superuser:
            try:
                org = Organization.objects.get(org_id=org_id)
            except Organization.DoesNotExist:
                return Response({"error": "Organization not found"}, status=404)
        else:
            membership = request.user.memberships.filter(
                organization__org_id=org_id, role="admin"
            ).first()
            if not membership:
                return Response({"error": "Organization not found or unauthorized"}, status=404)
            org = membership.organization

        # Check for existing user
        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already taken"}, status=409)
        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already registered"}, status=409)

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=full_name.split(" ")[0] if full_name else "",
            last_name=" ".join(full_name.split(" ")[1:]) if full_name and len(full_name.split(" ")) > 1 else "",
        )

        # Assign to org
        OrganizationMembership.objects.create(
            user=user,
            organization=org,
            role=role,
        )
        UserProfile.objects.update_or_create(
            user=user,
            defaults={"phone_number": phone_number},
        )

        return Response(
            {
                "message": "User created successfully",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "full_name": full_name,
                    "phone_number": phone_number,
                    "organization_id": org.org_id,
                    "organization": org.name,
                    "role": role,
                },
            },
            status=status.HTTP_201_CREATED,
        )


class ListOrganizationUsersView(APIView):
    """
    List all users belonging to a specific organization (admin only).
    """
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request, org_id):
        # Verify admin has access to this org
        if request.user.is_superuser:
            try:
                org = Organization.objects.get(org_id=org_id)
            except Organization.DoesNotExist:
                return Response({"error": "Organization not found"}, status=404)
        else:
            membership = request.user.memberships.filter(
                organization__org_id=org_id, role="admin"
            ).first()
            if not membership:
                return Response({"error": "Not authorized"}, status=403)
            org = membership.organization

        members = OrganizationMembership.objects.filter(
            organization=org
        ).select_related("user", "organization")

        data = []
        for m in members:
            data.append({
                "id": m.user.id,
                "username": m.user.username,
                "email": m.user.email,
                "full_name": f"{m.user.first_name} {m.user.last_name}".strip(),
                "is_active": m.user.is_active,
                "role": m.role,
                "joined_at": m.joined_at,
            })

        return Response(data)
