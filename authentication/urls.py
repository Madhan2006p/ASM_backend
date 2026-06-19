from django.urls import path

from .views import (
    AdminCreateUserView,
    AdminAllUsersView,
    CheckAuthView,
    ListFeaturesView,
    ListOrganizationUsersView,
    LoginView,
    LogoutView,
    OrganizationDetailView,
    OrganizationListView,
    OrganizationMembersView,
    ProfileView,
    RegisterView,
    UserFeatureManagementView,
    UserDomainManagementView,
    UserRoleManagementView,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("check-auth/", CheckAuthView.as_view(), name="check-auth"),
    # Feature management
    path("features/", ListFeaturesView.as_view(), name="list-features"),
    path("admin/users/<int:user_id>/features/", UserFeatureManagementView.as_view(), name="user-features"),
    path("admin/users/<int:user_id>/role/", UserRoleManagementView.as_view(), name="user-role"),
    # Organization management
    path("organizations/", OrganizationListView.as_view(), name="org-list"),
    path("organizations/<str:org_id>/", OrganizationDetailView.as_view(), name="org-detail"),
    path("organizations/<str:org_id>/members/", OrganizationMembersView.as_view(), name="org-members"),
    # Admin: user management
    path("admin/create-user/", AdminCreateUserView.as_view(), name="admin-create-user"),
    path("admin/users/", AdminAllUsersView.as_view(), name="admin-all-users"),
    path("admin/users/<int:user_id>/domains/", UserDomainManagementView.as_view(), name="user-domains"),
    path("admin/organizations/<str:org_id>/users/", ListOrganizationUsersView.as_view(), name="admin-org-users"),
]
