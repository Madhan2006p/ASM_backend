from django import forms
from django.contrib.auth.forms import UserChangeForm

from authentication.models import OrganizationMembership, UserProfile

from .models import Organization, User


def split_full_name(full_name):
    parts = full_name.strip().split(maxsplit=1)
    first_name = parts[0] if parts else ""
    last_name = parts[1] if len(parts) > 1 else ""
    return first_name, last_name


class AdminUserFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        instance = getattr(self, "instance", None)
        if instance and instance.pk:
            self.fields["full_name"].initial = instance.get_full_name()
            profile = getattr(instance, "asm_profile", None)
            if profile:
                self.fields["phone_number"].initial = profile.phone_number
                self.fields["features"].initial = profile.features
            membership = (
                instance.memberships.select_related("organization").first()
                if hasattr(instance, "memberships")
                else None
            )
            if membership:
                self.fields["organization"].initial = membership.organization_id

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip().lower()
        if not email:
            raise forms.ValidationError("Email Address is required.")

        queryset = User.objects.filter(email__iexact=email)
        if self.instance and self.instance.pk:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise forms.ValidationError("A user with this email already exists.")

        return email

    def save_profile_and_membership(self, user):
        full_name = self.cleaned_data.get("full_name", "")
        user.first_name, user.last_name = split_full_name(full_name)
        user.email = self.cleaned_data["email"]
        if not user.username:
            user.username = user.email
        user.save()

        UserProfile.objects.update_or_create(
            user=user,
            defaults={"phone_number": self.cleaned_data.get("phone_number", "")},
        )

        organization = self.cleaned_data.get("organization")
        if organization:
            existing = OrganizationMembership.objects.filter(
                user=user,
                organization=organization,
            ).first()
            role = existing.role if existing else ("admin" if user.is_staff or user.is_superuser else "member")
            OrganizationMembership.objects.update_or_create(
                user=user,
                organization=organization,
                defaults={"role": role},
            )

        return user


class CustomUserCreationForm(AdminUserFormMixin, forms.ModelForm):
    full_name = forms.CharField(label="Full Name", required=False, max_length=255)
    phone_number = forms.CharField(label="Phone Number", required=False, max_length=50)
    organization = forms.ModelChoiceField(
        label="Organization",
        queryset=Organization.objects.all(),
        required=False,
    )
    features = forms.CharField(
        label="Features",
        required=False,
        max_length=500,
        widget=forms.TextInput(attrs={"placeholder": "e.g., 1,2,3"}),
        help_text=(
            "Comma-separated feature IDs. Leave empty to unlock all features.<br>"
            "1=Subdomains, 2=Endpoints, 3=Open Ports, 4=Directories,<br>"
            "5=Technologies, 6=Vulnerabilities, 7=SSL Certificates,<br>"
            "8=Email Security, 9=Scan History"
        ),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput,
        help_text=(
            "Your password can't be too similar to your other personal information.<br>"
            "Your password must contain at least 8 characters.<br>"
            "Your password can't be a commonly used password.<br>"
            "Your password can't be entirely numeric."
        ),
    )
    password_confirmation = forms.CharField(
        label="Password confirmation",
        widget=forms.PasswordInput,
        help_text="Enter the same password as before, for verification.",
    )

    class Meta:
        model = User
        fields = ("email", "full_name", "phone_number", "organization", "features", "is_staff", "is_active")

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirmation = cleaned_data.get("password_confirmation")

        if password and password_confirmation and password != password_confirmation:
            self.add_error("password_confirmation", "Passwords do not match")

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data["email"]
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
            self.save_m2m()
            self.save_profile_and_membership(user)
        # Save features to UserProfile regardless of commit -
        # Django admin calls form.save(commit=False) internally,
        # so we need to persist features even when commit=False.
        # Guard with user.pk: for new unsaved users, the admin will
        # call save_model() which calls obj.save() to persist the user first.
        if user.pk:
            from authentication.models import UserProfile
            UserProfile.objects.update_or_create(
                user=user,
                defaults={"features": self.cleaned_data.get("features", ""),
                          "phone_number": self.cleaned_data.get("phone_number", "")},
            )
        return user


class CustomUserChangeForm(AdminUserFormMixin, UserChangeForm):
    full_name = forms.CharField(label="Full Name", required=False, max_length=255)
    phone_number = forms.CharField(label="Phone Number", required=False, max_length=50)
    organization = forms.ModelChoiceField(
        label="Organization",
        queryset=Organization.objects.all(),
        required=False,
    )
    features = forms.CharField(
        label="Features",
        required=False,
        max_length=500,
        widget=forms.TextInput(attrs={"placeholder": "e.g., 1,2,3"}),
        help_text=(
            "Comma-separated feature IDs. Leave empty to unlock all features.<br>"
            "1=Subdomains, 2=Endpoints, 3=Open Ports, 4=Directories,<br>"
            "5=Technologies, 6=Vulnerabilities, 7=SSL Certificates,<br>"
            "8=Email Security, 9=Scan History"
        ),
    )

    class Meta:
        model = User
        fields = (
            "email",
            "password",
            "full_name",
            "phone_number",
            "organization",
            "features",
            "is_active",
            "is_staff",
            "is_superuser",
            "groups",
            "user_permissions",
        )

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
            self.save_m2m()
            self.save_profile_and_membership(user)
        # Save features to UserProfile regardless of commit -
        # Django admin calls form.save(commit=False) internally,
        # so we need to persist features even when commit=False.
        if user.pk:
            from authentication.models import UserProfile
            UserProfile.objects.update_or_create(
                user=user,
                defaults={"features": self.cleaned_data.get("features", "")},
            )
        return user
