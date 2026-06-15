import re

from django.contrib.auth.models import User
from rest_framework import serializers

from .models import Organization, OrganizationMembership, UserProfile


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    name = serializers.CharField(source="username", read_only=True)
    confirm_password = serializers.CharField(write_only=True, required=False)
    phone = serializers.CharField(write_only=True, required=False, allow_blank=True)
    organization = serializers.CharField(write_only=True, required=False, allow_blank=True)
    # Explicitly define username to avoid pulling Django User model validators
    # (which reject spaces). We sanitize in validate_username instead.
    username = serializers.CharField(max_length=150)

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "name",
            "email",
            "password",
            "confirm_password",
            "phone",
            "organization",
        )

    def validate_username(self, value):
        """Sanitize username: replace invalid characters with underscores."""
        sanitized = re.sub(r"[^\w.@+-]+", "_", value).strip("_")
        if not sanitized:
            raise serializers.ValidationError(
                "Username must contain at least one valid character (letters, numbers, @/./+/-/_)"
            )
        return sanitized

    def validate(self, data):
        data.pop("phone", None)  # consumed here — not a User model field
        confirm = data.pop("confirm_password", None)
        if confirm and data.get("password") != confirm:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        # Check for duplicate username
        username = data.get("username")
        if username and User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                {"username": "A user with this username already exists."}
            )

        # Check for duplicate email
        email = data.get("email")
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                {"email": "A user with this email address already exists."}
            )

        return data

    def create(self, validated_data):
        org_name = validated_data.pop("organization", None) or f"{validated_data.get('username', 'User')}'s Org"
        user = User.objects.create_user(
            username=validated_data.get("username") or validated_data.get("email", ""),
            email=validated_data.get("email", ""),
            password=validated_data["password"],
        )
        UserProfile.objects.update_or_create(
            user=user,
            defaults={"phone_number": self.initial_data.get("phone", "")},
        )
        # Create or get organization and add membership
        org, _ = Organization.objects.get_or_create(
            name=org_name,
            defaults={"org_id": org_name.lower().replace(" ", "-")[:50]},
        )
        OrganizationMembership.objects.get_or_create(
            user=user,
            organization=org,
            defaults={"role": "admin"},
        )
        return user


class OrganizationSerializer(serializers.ModelSerializer):
    member_count = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ("id", "name", "org_id", "created_at", "member_count", "role")

    def get_member_count(self, obj):
        return obj.memberships.count()

    def get_role(self, obj):
        user = self.context.get("request").user if self.context.get("request") else None
        if user:
            membership = obj.memberships.filter(user=user).first()
            if membership:
                return membership.role
        return None


class OrganizationMembershipSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source="user.username", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)
    org_name = serializers.CharField(source="organization.name", read_only=True)

    class Meta:
        model = OrganizationMembership
        fields = (
            "id",
            "user",
            "user_name",
            "user_email",
            "organization",
            "org_name",
            "role",
            "joined_at",
        )
        read_only_fields = ("user", "joined_at")
