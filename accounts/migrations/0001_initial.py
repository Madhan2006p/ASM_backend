from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("authentication", "0003_organization_admin_fields_userprofile"),
    ]

    operations = [
        migrations.CreateModel(
            name="Organization",
            fields=[],
            options={
                "verbose_name": "Organization",
                "verbose_name_plural": "Organizations",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("authentication.organization",),
        ),
        migrations.CreateModel(
            name="User",
            fields=[],
            options={
                "verbose_name": "User",
                "verbose_name_plural": "Users",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("auth.user",),
        ),
    ]
