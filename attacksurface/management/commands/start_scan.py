import re
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from attacksurface.models import AttackSurfaceScan
from attacksurface.views import run_full_scan

User = get_user_model()

class Command(BaseCommand):
    help = 'Starts an attack surface scan for a specific user and domain'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, required=True, help='Email of the user initiating the scan')
        parser.add_argument('--domain', type=str, required=True, help='Target domain to scan')

    def handle(self, *args, **options):
        email = options['email']
        target = options['domain']

        # Normalize target
        target = target.strip().lower()
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0].split(':')[0]
        target = re.sub(r'^www\.', '', target)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            self.stderr.write(self.style.ERROR(f"User with email '{email}' does not exist."))
            return

        # Find org ID
        membership = user.memberships.select_related("organization").first() if hasattr(user, "memberships") else None
        org_id = membership.organization.org_id if membership and membership.organization else "1"

        self.stdout.write(self.style.SUCCESS(f"Starting scan for domain '{target}' (User: {email}, Org ID: {org_id})..."))

        scan = AttackSurfaceScan.objects.create(
            target=target, org_id=org_id, status="pending"
        )

        try:
            # Run the scan synchronously so the command doesn't exit immediately
            run_full_scan(scan)
            self.stdout.write(self.style.SUCCESS(f"Scan for '{target}' completed successfully."))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Scan failed: {str(e)}"))
            scan.status = "failed"
            scan.save()
