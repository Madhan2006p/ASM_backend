import re
import time
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from attacksurface.models import AttackSurfaceScan
from attacksurface.views import run_full_scan

User = get_user_model()


def _save_vulns_to_db(scan, target, findings):
    """Persist findings dicts to VulnerabilityResult, deduplicated per scan."""
    from attacksurface.models import VulnerabilityResult
    from attacksurface.scanner.vulnerability_scanner import deduplicate_vulnerabilities

    saved = 0
    for item in deduplicate_vulnerabilities(findings):
        vuln_id = item.get("vulnerability_id") or item.get("template_id") or "PYTHON-VULN"
        host = item.get("subdomain") or item.get("host") or target
        vr, created = VulnerabilityResult.objects.get_or_create(
            scan=scan,
            vulnerability_id=vuln_id,
            subdomain=host,
            defaults={
                "domain": target,
                "severity": str(item.get("severity") or "info").lower(),
                "cve": item.get("cve", ""),
                "cwe": item.get("cwe", ""),
                "finding": item.get("finding") or item.get("name") or "Vulnerability Discovered",
                "description": item.get("description", ""),
                "remediation": item.get("remediation", ""),
                "reference": item.get("reference", ""),
                "template_id": item.get("template_id", ""),
                "source_tool": item.get("source_tool", "PythonScanner"),
                "org_id": scan.org_id,
            },
        )
        if created:
            saved += 1
    return saved


class Command(BaseCommand):
    help = 'Starts an attack surface scan for a specific user and domain (with live terminal progress)'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, required=True, help='Email of the user initiating the scan')
        parser.add_argument('--domain', type=str, required=True, help='Target domain to scan')
        parser.add_argument('--vuln-only', action='store_true',
                            help='Only run the vulnerability scan (basic + deep), skipping recon phases')

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

        self.stdout.write(self.style.SUCCESS(f"\n▶ Starting scan for domain '{target}' (User: {email}, Org ID: {org_id})...\n"))

        scan = AttackSurfaceScan.objects.create(
            target=target, org_id=org_id, status="pending"
        )

        try:
            if options['vuln_only']:
                self.handle_vuln_only(scan, target)
            else:
                # Run the scan synchronously so progress prints live to the terminal
                run_full_scan(scan)
                # run_full_scan swallows exceptions internally and sets status itself,
                # so re-read the DB to report the real outcome.
                scan.refresh_from_db()
                if scan.status == "failed":
                    self.stderr.write(self.style.ERROR(
                        f"\n✗ Scan for '{target}' failed: {scan.error_message[:300] or 'unknown error'}"
                    ))
                else:
                    self.stdout.write(self.style.SUCCESS(f"\n✓ Scan for '{target}' completed successfully."))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"\n✗ Scan failed: {str(e)}"))
            scan.status = "failed"
            scan.error_message = str(e)
            scan.save()

        # Print a compact summary
        scan.refresh_from_db()
        from attacksurface.models import SubdomainResult, VulnerabilityResult
        sub_count = SubdomainResult.objects.filter(scan=scan).count()
        vuln_count = VulnerabilityResult.objects.filter(scan=scan).count()
        self.stdout.write(self.style.SUCCESS(
            f"\n━━━ SCAN SUMMARY (id={scan.id}) ━━━\n"
            f"  Target : {target}\n"
            f"  Status : {scan.status} ({scan.progress}%)\n"
            f"  Subdomains : {sub_count}\n"
            f"  Vulnerabilities : {vuln_count}\n"
        ))

    def handle_vuln_only(self, scan, target):
        """Run the vulnerability scan only: basic inline scan + deep engine, with live progress."""
        from attacksurface.services import log_scan_progress, run_python_vuln_scanner
        from attacksurface.deep_nuclei_scan import get_live_state, start_deep_scan_thread
        from attacksurface.models import VulnerabilityResult

        scan.status = "running"
        scan.progress = 70
        scan.vuln_scan_phase = "running_basic"
        scan.save()

        self.stdout.write(self.style.WARNING(f"\n🔍 Vulnerability-only scan for '{target}'..."))

        # Basic inline scan (headers, exposures, misconfigs, sensitive ports)
        httpx_items = [{"url": f"https://{target}", "headers": {}, "status_code": 0}]
        findings = run_python_vuln_scanner(target, httpx_items)
        saved = _save_vulns_to_db(scan, target, findings)
        log_scan_progress(scan, f"Basic vuln scan: {len(findings)} findings ({saved} new)")

        # Deep scan engine (streams results phase by phase)
        scan.vuln_scan_phase = "running_deep"
        scan.save(update_fields=["vuln_scan_phase"])
        start_deep_scan_thread(scan.id, target, [f"https://{target}"])

        # Poll live state and print progress until done (bounded so a dead
        # background thread can never hang the command forever).
        last_phase = ""
        deadline = time.time() + 900  # 15 min safety cap
        while time.time() < deadline:
            time.sleep(2)
            scan.refresh_from_db()
            live = get_live_state(scan.id)
            phase_name = live.get("phase_name") or scan.nuclei_phase or ""
            if phase_name and phase_name != last_phase:
                self.stdout.write(f"  ▶ {phase_name} ...")
                last_phase = phase_name
            if scan.status in ("completed", "failed"):
                break
            if scan.vuln_scan_phase == "complete" or live.get("status") == "complete":
                # Give the thread a moment to persist final counts
                time.sleep(1)
                break
        else:
            self.stderr.write(self.style.WARNING(
                "\n⚠ Timed out waiting for the deep scan thread — results saved so far are kept."
            ))

        scan.refresh_from_db()
        scan.status = "completed"
        scan.progress = 100
        scan.vulnerabilities_done = True
        scan.save(update_fields=["status", "progress", "vulnerabilities_done"])

        final_count = VulnerabilityResult.objects.filter(scan=scan).count()
        self.stdout.write(self.style.SUCCESS(
            f"\n✓ Vulnerability scan finished: {scan.vuln_scan_phase} | "
            f"{final_count} vulnerabilities stored"
        ))
