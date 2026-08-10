from django.contrib.auth import authenticate, get_user_model
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Organization, OrganizationMembership, UserDomain, UserProfile
from .permissions import IsOrgAdmin, IsAuthenticatedAndOrgMember
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


def get_user_data(user, request=None):
    membership = (
        user.memberships.select_related("organization").first()
        if hasattr(user, "memberships") and user.pk
        else None
    )
    org_id = "1"
    org_name = "Default Org"
    role = "member"
    logo_url = None
    if membership:
        org_id = membership.organization.org_id
        org_name = membership.organization.name
        role = membership.role
        if membership.organization.logo:
            logo_url = membership.organization.logo.url
            if request:
                logo_url = request.build_absolute_uri(logo_url)

    # Ensure UserProfile exists for feature support & domain admin fields
    profile = getattr(user, "asm_profile", None)
    if not profile:
        profile = UserProfile.objects.get_or_create(user=user)[0]

    # Parse features - comma-separated IDs, empty means all unlocked
    features = []
    if profile.features:
        features = [f.strip() for f in profile.features.split(",") if f.strip()]

    # Load organization-shared domains (UserDomain pool + Organization.allowed_domains)
    assigned_domains = set()
    if membership and membership.organization:
        if membership.organization.allowed_domains:
            for d in membership.organization.allowed_domains.split(","):
                d_str = d.strip()
                if d_str:
                    assigned_domains.add(d_str)
        member_user_ids = OrganizationMembership.objects.filter(
            organization=membership.organization
        ).values_list("user", flat=True)
        for d in UserDomain.objects.filter(user_id__in=member_user_ids).values_list("domain__domain", flat=True):
            assigned_domains.add(d)
    assigned_domains = list(assigned_domains)

    profile_photo_url = profile.profile_photo.url if profile and profile.profile_photo else None
    if request and profile_photo_url:
        profile_photo_url = request.build_absolute_uri(profile_photo_url)

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
        "logo_url": logo_url,
        "profile_photo_url": profile_photo_url,
        "is_superuser": user.is_superuser,
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
                "user": get_user_data(user, request),
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email_or_user = request.data.get("email") or request.data.get("username") or ""
        password = request.data.get("password", "")

        username = email_or_user
        if email_or_user:
            user_obj = User.objects.filter(username__iexact=email_or_user).first()
            if not user_obj:
                user_obj = User.objects.filter(email__iexact=email_or_user).first()
            if user_obj:
                username = user_obj.username

        user = authenticate(request=request, username=username, password=password)
        if not user and username:
            try:
                u = User.objects.filter(username__iexact=username).first()
                if u and u.check_password(password) and u.is_active:
                    user = u
            except Exception:
                pass

        if not user:
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        tokens = get_tokens_for_user(user)
        return Response(
            {
                "tokens": tokens,
                "user": get_user_data(user, request),
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
        return Response(get_user_data(request.user, request))

    def put(self, request):
        user = request.user
        profile = getattr(user, "asm_profile", None)
        if not profile:
            profile = UserProfile.objects.create(user=user)
        
        # Handle profile photo upload
        if 'profile_photo' in request.FILES:
            profile.profile_photo = request.FILES['profile_photo']
            profile.save()

        # Handle other fields (name, phone, etc) if needed
        if 'name' in request.data:
            user.first_name = request.data['name']
            user.save()
        if 'phone_number' in request.data:
            profile.phone_number = request.data['phone_number']
            profile.save()

        return Response(get_user_data(user, request))


class CheckAuthView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"authenticated": True, "user": get_user_data(request.user, request)})


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
        
        logo = request.FILES.get("logo")
        logo_file = None
        if logo:
            import os
            ext = os.path.splitext(logo.name)[1].lower()
            if ext != '.svg':
                return Response({"error": "Only SVG format is allowed for logos."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                content = logo.read(1000).decode('utf-8', errors='ignore')
                logo.seek(0)
                if '<svg' not in content.lower():
                    return Response({"error": "Invalid SVG file content."}, status=status.HTTP_400_BAD_REQUEST)
            except Exception:
                return Response({"error": "Failed to read SVG file content."}, status=status.HTTP_400_BAD_REQUEST)
            logo_file = logo

        org = Organization.objects.create(
            name=name, 
            org_id=name.lower().replace(" ", "-")[:50],
            logo=logo_file
        )
        OrganizationMembership.objects.get_or_create(
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
        if request.user.is_superuser:
            org = Organization.objects.filter(org_id=org_id).first()
            if not org:
                return Response({"error": "Organization not found"}, status=404)
        else:
            membership = request.user.memberships.filter(
                organization__org_id=org_id, role="admin"
            ).first()
            if not membership:
                return Response({"error": "Not authorized"}, status=403)
            org = membership.organization
            
        name = request.data.get("name")
        if name:
            org.name = name.strip()
            
        logo = request.FILES.get("logo")
        if logo:
            import os
            ext = os.path.splitext(logo.name)[1].lower()
            if ext != '.svg':
                return Response({"error": "Only SVG format is allowed for logos."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                content = logo.read(1000).decode('utf-8', errors='ignore')
                logo.seek(0)
                if '<svg' not in content.lower():
                    return Response({"error": "Invalid SVG file content."}, status=status.HTTP_400_BAD_REQUEST)
            except Exception:
                return Response({"error": "Failed to read SVG file content."}, status=status.HTTP_400_BAD_REQUEST)
            org.logo = logo
            
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
    {"id": "1", "name": "Asset Discovery", "module": "asset_discovery", "description": "Discover subdomains, endpoints, open ports, directories, technologies, vulnerabilities, and SSL certificates"},
    {"id": "2", "name": "Mobile Security", "module": "apk_scanner", "description": "Scan mobile apps for security vulnerabilities"},
    {"id": "3", "name": "Email Security", "module": "email_security", "description": "Analyze email security configurations and records"},
    {"id": "4", "name": "Internal Asset Discovery", "module": "internal_asset", "description": "Discover internal networks, services, active directory, and assets"},
    {"id": "5", "name": "Surface Web Monitoring", "module": "surface_web", "description": "Monitor brand presence on the surface web"},
    {"id": "6", "name": "Brand Monitoring", "module": "brand_monitoring", "description": "Monitor brand abuse, anti-malware, and phishing"},
]


class ListFeaturesView(APIView):
    """
    List all available features that can be given/taken from users.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"features": AVAILABLE_FEATURES})


class UserFeatureManagementView(APIView):
    """
    Manage features for a specific user.
    - GET: List the user's granted features (viewable by any org member)
    - POST (give): Grant a feature to the user (admin only)
    - POST (take): Revoke a feature from the user (admin only)
    """
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

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

        # Ensure requester is an admin in the target user's organization
        if not request.user.is_superuser:
            admin_membership = request.user.memberships.filter(
                organization__memberships__user=target_user, role="admin"
            ).first()
            if not admin_membership:
                return Response({"error": "Only organization administrators can modify user features."}, status=403)

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
            # Organization admins can only assign features that they themselves possess
            if not request.user.is_superuser:
                admin_profile = getattr(request.user, "asm_profile", None)
                admin_features = set()
                if admin_profile and admin_profile.features:
                    admin_features = set(f.strip() for f in admin_profile.features.split(",") if f.strip())
                if feature_id not in admin_features:
                    return Response(
                        {"error": "You are not authorized to assign this feature. Your organization has not been granted this feature by the super admin."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
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

        # Super admin only can create admin user for an organization
        if role == "admin" and not request.user.is_superuser:
            return Response(
                {"error": "Only super admins can create admin users."},
                status=status.HTTP_403_FORBIDDEN,
            )

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
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get(self, request, org_id):
        # Verify admin has access to this org
        if request.user.is_superuser:
            try:
                org = Organization.objects.get(org_id=org_id)
            except Organization.DoesNotExist:
                return Response({"error": "Organization not found"}, status=404)
        else:
            membership = request.user.memberships.filter(
                organization__org_id=org_id
            ).first()
            if not membership:
                return Response({"error": "Not authorized"}, status=403)
            org = membership.organization

        members = OrganizationMembership.objects.filter(
            organization=org
        ).select_related("user", "organization")

        data = []
        for m in members:
            profile = getattr(m.user, "asm_profile", None)
            photo_url = None
            if profile and profile.profile_photo:
                photo_url = profile.profile_photo.url
                if request:
                    photo_url = request.build_absolute_uri(photo_url)
            data.append({
                "id": m.user.id,
                "username": m.user.username,
                "email": m.user.email,
                "full_name": f"{m.user.first_name} {m.user.last_name}".strip(),
                "is_active": m.user.is_active,
                "is_superuser": m.user.is_superuser,
                "role": m.role,
                "organization": m.organization.name,
                "profile_photo_url": photo_url,
                "joined_at": m.joined_at,
            })

        return Response(data)

class AdminAllUsersView(APIView):
    """
    List all users across all organizations (superuser only).
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=403)

        members = OrganizationMembership.objects.select_related("user", "organization").all()
        
        data = []
        for m in members:
            logo_url = None
            if m.organization.logo:
                logo_url = m.organization.logo.url
                if request:
                    logo_url = request.build_absolute_uri(logo_url)
            data.append({
                "id": m.user.id,
                "username": m.user.username,
                "email": m.user.email,
                "full_name": f"{m.user.first_name} {m.user.last_name}".strip(),
                "is_active": m.user.is_active,
                "is_superuser": m.user.is_superuser,
                "role": m.role,
                "organization": m.organization.name,
                "organization_id": m.organization.org_id,
                "logo_url": logo_url,
                "joined_at": m.joined_at,
            })

        return Response(data)

class UserDomainManagementView(APIView):
    """
    Manage domains for a specific user (superuser only).
    - GET: List the user's assigned domains
    - POST (action=give): Assign a domain
    - POST (action=take): Remove a domain
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, user_id):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=403)
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
        
        from .models import UserDomain
        domains = UserDomain.objects.filter(user=target_user).values_list("domain__domain", flat=True)
        return Response({"user_id": target_user.id, "domains": list(domains)})

    def post(self, request, user_id):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=403)
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        action = request.data.get("action", "")
        domain_name = request.data.get("domain", "").strip().lower()

        if not domain_name:
            return Response({"error": "domain is required"}, status=400)

        import re
        domain_name = re.sub(r'^https?://', '', domain_name)
        domain_name = domain_name.split('/')[0].split(':')[0]
        domain_name = re.sub(r'^www\.', '', domain_name)

        from .models import Domain, UserDomain

        if action == "give":
            domain_obj, _ = Domain.objects.get_or_create(domain=domain_name)
            UserDomain.objects.get_or_create(user=target_user, domain=domain_obj)
            return Response({"message": f"Domain {domain_name} assigned to user"})
        elif action == "take":
            try:
                domain_obj = Domain.objects.get(domain=domain_name)
                UserDomain.objects.filter(user=target_user, domain=domain_obj).delete()
                return Response({"message": f"Domain {domain_name} removed from user"})
            except Domain.DoesNotExist:
                return Response({"message": "Domain not found"})
        else:
            return Response({"error": "action must be 'give' or 'take'"}, status=400)


class UserRoleManagementView(APIView):
    """
    Manage user roles within an organization.
    Only superusers or org admins can change roles.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, user_id):
        if not request.user.is_superuser:
            return Response({"error": "Only superusers can modify roles."}, status=403)

        role = request.data.get("role")
        if role not in ("admin", "member", "viewer"):
            return Response({"error": "Invalid role"}, status=400)

        target_user = get_object_or_404(User, id=user_id)
        
        # Currently the system assumes 1 organization per user in the frontend, so we just update their first membership
        membership = OrganizationMembership.objects.filter(user=target_user).first()
        if not membership:
            return Response({"error": "User does not belong to any organization."}, status=400)

        membership.role = role
        membership.save(update_fields=["role"])

        return Response({
            "message": f"User role updated to {role}",
            "role": role
        })
