import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("attacksurface", "0005_sslresult_ip_count_dns_count"),
        ("scans", "0006_alter_scan_scan_type"),
        ("targets", "0003_target_org_id_target_targets_tar_org_id_5c7443_idx"),
    ]

    operations = [
        migrations.CreateModel(
            name="Domain",
            fields=[],
            options={
                "verbose_name": "Domain",
                "verbose_name_plural": "Domains",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("targets.target",),
        ),
        migrations.CreateModel(
            name="Endpoint",
            fields=[],
            options={
                "verbose_name": "Endpoint",
                "verbose_name_plural": "Endpoints",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("targets.endpoint",),
        ),
        migrations.CreateModel(
            name="ScanEngine",
            fields=[],
            options={
                "verbose_name": "Scan Engine",
                "verbose_name_plural": "Scan Engines",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("scans.monitorschedule",),
        ),
        migrations.CreateModel(
            name="ScanHistory",
            fields=[],
            options={
                "verbose_name": "Scan History",
                "verbose_name_plural": "Scan History",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("scans.scan",),
        ),
        migrations.CreateModel(
            name="Subdomain",
            fields=[],
            options={
                "verbose_name": "Subdomain",
                "verbose_name_plural": "Subdomains",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("attacksurface.subdomainresult",),
        ),
        migrations.CreateModel(
            name="TestSSLScan",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("host", models.CharField(max_length=255)),
                ("port", models.CharField(default="443", max_length=10)),
                ("ip", models.CharField(blank=True, max_length=100, null=True)),
                ("grade", models.CharField(blank=True, max_length=10, null=True)),
                ("scanned_at", models.DateTimeField(auto_now_add=True)),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="testssl_records",
                        to="scans.scan",
                    ),
                ),
                (
                    "target",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="testssl_records",
                        to="targets.target",
                    ),
                ),
            ],
            options={
                "verbose_name": "TestSSL Scan",
                "verbose_name_plural": "TestSSL Scans",
            },
        ),
        migrations.CreateModel(
            name="TestSslRating",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("metric", models.CharField(blank=True, max_length=255, null=True)),
                ("score", models.CharField(blank=True, max_length=50, null=True)),
                ("finding", models.TextField(blank=True, null=True)),
                (
                    "testssl_scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ratings",
                        to="assetDiscovery.testsslscan",
                    ),
                ),
            ],
            options={
                "verbose_name": "Test ssl rating",
                "verbose_name_plural": "Test ssl ratings",
            },
        ),
        migrations.CreateModel(
            name="TestSslProtocol",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("protocol", models.CharField(blank=True, max_length=100, null=True)),
                ("status", models.CharField(blank=True, max_length=100, null=True)),
                ("finding", models.TextField(blank=True, null=True)),
                (
                    "testssl_scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="protocols",
                        to="assetDiscovery.testsslscan",
                    ),
                ),
            ],
            options={
                "verbose_name": "Test ssl protocol",
                "verbose_name_plural": "Test ssl protocols",
            },
        ),
        migrations.CreateModel(
            name="TestSslCipher",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("cipher", models.CharField(blank=True, max_length=255, null=True)),
                ("key_size", models.CharField(blank=True, max_length=50, null=True)),
                ("strength", models.CharField(blank=True, max_length=50, null=True)),
                ("status", models.CharField(blank=True, max_length=100, null=True)),
                ("finding", models.TextField(blank=True, null=True)),
                (
                    "testssl_scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ciphers",
                        to="assetDiscovery.testsslscan",
                    ),
                ),
            ],
            options={
                "verbose_name": "Test ssl cipher",
                "verbose_name_plural": "Test ssl ciphers",
            },
        ),
        migrations.CreateModel(
            name="TestSslBrowserSimulation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("client", models.CharField(blank=True, max_length=255, null=True)),
                ("version", models.CharField(blank=True, max_length=100, null=True)),
                ("status", models.CharField(blank=True, max_length=100, null=True)),
                ("cipher", models.CharField(blank=True, max_length=255, null=True)),
                ("dh_key_exchange", models.CharField(blank=True, max_length=255, null=True)),
                ("key_size", models.CharField(blank=True, max_length=50, null=True)),
                ("finding", models.TextField(blank=True, null=True)),
                (
                    "testssl_scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="browser_simulations",
                        to="assetDiscovery.testsslscan",
                    ),
                ),
            ],
            options={
                "verbose_name": "Test ssl browser simulation",
                "verbose_name_plural": "Test ssl browser simulations",
            },
        ),
        migrations.CreateModel(
            name="TestSslServerDefault",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("setting", models.CharField(blank=True, max_length=255, null=True)),
                ("value", models.TextField(blank=True, null=True)),
                ("finding", models.TextField(blank=True, null=True)),
                (
                    "testssl_scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="server_defaults",
                        to="assetDiscovery.testsslscan",
                    ),
                ),
            ],
            options={
                "verbose_name": "Test ssl server default",
                "verbose_name_plural": "Test ssl server defaults",
            },
        ),
        migrations.CreateModel(
            name="TestSslServerPreference",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("preference_type", models.CharField(blank=True, max_length=255, null=True)),
                ("value", models.TextField(blank=True, null=True)),
                ("finding", models.TextField(blank=True, null=True)),
                (
                    "testssl_scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="server_preferences",
                        to="assetDiscovery.testsslscan",
                    ),
                ),
            ],
            options={
                "verbose_name": "Test ssl server preference",
                "verbose_name_plural": "Test ssl server preferences",
            },
        ),
        migrations.CreateModel(
            name="TestSslVulnerability",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("vulnerability", models.CharField(blank=True, max_length=255, null=True)),
                ("severity", models.CharField(blank=True, max_length=50, null=True)),
                ("status", models.CharField(blank=True, max_length=100, null=True)),
                ("finding", models.TextField(blank=True, null=True)),
                (
                    "testssl_scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="vulnerabilities",
                        to="assetDiscovery.testsslscan",
                    ),
                ),
            ],
            options={
                "verbose_name": "Test ssl vulnerability",
                "verbose_name_plural": "Test ssl vulnerabilities",
            },
        ),
    ]
