from django.db import migrations


def seed_default_org(apps, schema_editor):
    Organization = apps.get_model("authentication", "Organization")
    Organization.objects.get_or_create(
        name="Default Org",
        defaults={"org_id": "1"},
    )


def link_existing_users(apps, schema_editor):
    """Add existing users to the default org with admin role."""
    Organization = apps.get_model("authentication", "Organization")
    OrganizationMembership = apps.get_model("authentication", "OrganizationMembership")
    User = apps.get_model("auth", "User")

    org, _ = Organization.objects.get_or_create(
        name="Default Org",
        defaults={"org_id": "1"},
    )
    for user in User.objects.all():
        OrganizationMembership.objects.get_or_create(
            user=user,
            organization=org,
            defaults={"role": "admin"},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0001_add_organization_and_membership"),
    ]

    operations = [
        migrations.RunPython(seed_default_org, reverse_code=migrations.RunPython.noop),
        migrations.RunPython(link_existing_users, reverse_code=migrations.RunPython.noop),
    ]
