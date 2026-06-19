from django.contrib import admin
from django.contrib.admin.sites import NotRegistered
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User as DjangoUser
from django.utils.text import slugify

from authentication.models import Domain as AuthDomain, OrganizationMembership, UserDomain, UserProfile

from .forms import CustomUserChangeForm, CustomUserCreationForm
from .models import Organization, User


def unique_org_id(name):
    base = slugify(name)[:50] or "org"
    candidate = base
    counter = 2

    while Organization.objects.filter(org_id=candidate).exists():
        suffix = f"-{counter}"
        candidate = f"{base[:50 - len(suffix)]}{suffix}"
        counter += 1

    return candidate


class OrganizationListFilter(admin.SimpleListFilter):
    title = "organization"
    parameter_name = "organization"

    def lookups(self, request, model_admin):
        return Organization.objects.order_by("name").values_list("id", "name")

    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(memberships__organization_id=self.value())
        return queryset


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "org_id", "is_active", "member_count", "created_at")
    list_filter = ("is_active", "created_at")
    search_fields = ("name", "org_id", "allowed_domains")
    readonly_fields = ("created_at", "updated_at")
    ordering = ("name",)

    fieldsets = (
        (None, {"fields": ("name", "description", "logo", "is_active")}),
        (
            "Domains",
            {
                "fields": ("allowed_domains",),
                "description": "Enter domains separated by commas (e.g., example.com,test.org)",
            },
        ),
        ("Timestamps", {"classes": ("collapse",), "fields": ("created_at", "updated_at")}),
    )

    def save_model(self, request, obj, form, change):
        proposed_org_id = (obj.org_id or "").strip()
        if not change and (
            not proposed_org_id or Organization.objects.filter(org_id=proposed_org_id).exists()
        ):
            obj.org_id = unique_org_id(obj.name)
        else:
            obj.org_id = proposed_org_id

        super().save_model(request, obj, form, change)

    @admin.display(description="Members")
    def member_count(self, obj):
        return obj.memberships.count()


try:
    admin.site.unregister(DjangoUser)
except NotRegistered:
    pass


class UserDomainInline(admin.TabularInline):
    model = UserDomain
    extra = 1
    verbose_name = "Assign Domain"
    verbose_name_plural = "Assigned Domains"
    fields = ("domain",)
    autocomplete_fields = ("domain",)


@admin.register(AuthDomain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ("domain", "assigned_user_count", "created_at")
    search_fields = ("domain",)
    ordering = ("domain",)
    readonly_fields = ("created_at",)

    fieldsets = (
        (None, {"fields": ("domain", "description")}),
        ("Timestamps", {"classes": ("collapse",), "fields": ("created_at",)}),
    )

    @admin.display(description="Assigned Users")
    def assigned_user_count(self, obj):
        return obj.assigned_users.count()


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    inlines = [UserDomainInline]
    list_display = (
        "email",
        "full_name",
        "phone_number",
        "organization",
        "features_display",
        "is_staff",
        "is_active",
    )
    list_filter = ("is_staff", "is_active", OrganizationListFilter)
    search_fields = ("email", "username", "first_name", "last_name", "asm_profile__phone_number")
    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("full_name", "phone_number", "organization")}),
        ("Feature Access", {
            "fields": ("features",),
            "description": "Comma-separated feature IDs. Leave empty to unlock all features.\n"
            "1=Subdomains, 2=Endpoints, 3=Open Ports, 4=Directories,\n"
            "5=Technologies, 6=Vulnerabilities, 7=SSL Certificates,\n"
            "8=Email Security, 9=Scan History",
        }),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser")}),
        ("Groups", {"fields": ("groups",)}),
        ("User permissions", {"fields": ("user_permissions",)}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "full_name",
                    "phone_number",
                    "organization",
                    "features",
                    "password",
                    "password_confirmation",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )

    filter_horizontal = ("groups", "user_permissions")

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.prefetch_related("memberships__organization").select_related("asm_profile")

    @admin.display(description="Full Name")
    def full_name(self, obj):
        return obj.get_full_name()

    @admin.display(description="Phone Number")
    def phone_number(self, obj):
        profile = getattr(obj, "asm_profile", None)
        return profile.phone_number if profile else ""

    @admin.display(description="Organization")
    def organization(self, obj):
        membership = (
            OrganizationMembership.objects.select_related("organization")
            .filter(user=obj)
            .first()
        )
        return membership.organization if membership else None

    @admin.display(description="Features")
    def features_display(self, obj):
        profile = getattr(obj, "asm_profile", None)
        if profile and profile.features:
            feature_ids = [f.strip() for f in profile.features.split(",") if f.strip()]
            feature_names = {
                "1": "Subdomains", "2": "Endpoints", "3": "Open Ports",
                "4": "Directories", "5": "Technologies", "6": "Vulnerabilities",
                "7": "SSL", "8": "Email", "9": "Scans",
            }
            labels = [feature_names.get(fid, fid) for fid in feature_ids]
            return ", ".join(labels)
        return "All unlocked"


