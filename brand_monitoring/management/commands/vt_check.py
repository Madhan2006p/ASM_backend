import os
import json
import time

import requests
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from brand_monitoring.models import BrandMonitorTarget
from brand_monitoring.tasks import _create_report, _get_vt_headers

VT_API_BASE = "https://www.virustotal.com/api/v3"


class Command(BaseCommand):
    help = "VirusTotal anti-malware scan for brand monitoring domains"

    def add_arguments(self, parser):
        parser.add_argument(
            "domain", nargs="?", type=str, help="Domain to scan (e.g. example.com)"
        )
        parser.add_argument(
            "--all", action="store_true", help="Scan all active targets"
        )
        parser.add_argument(
            "--add", action="store_true", help="Add domain as a persistent target before scanning"
        )
        parser.add_argument(
            "--org", type=str, default="1", help="Organization ID (default: 1)"
        )
        parser.add_argument(
            "--json", action="store_true", help="Output raw JSON (like jq .data.attributes.last_analysis_stats)"
        )
        parser.add_argument(
            "--save", action="store_true", help="Save report to database"
        )

    def handle(self, *args, **options):
        domains = []

        if options["all"]:
            targets = BrandMonitorTarget.objects.filter(is_active=True)
            if not targets:
                self.stdout.write(self.style.WARNING("No active targets found"))
                return
            domains = [(t.domain, t.id) for t in targets]
            self.stdout.write(f"Scanning {len(domains)} active target(s)...")

        elif options["domain"]:
            domain = options["domain"].strip()

            if options["add"]:
                target, created = BrandMonitorTarget.objects.get_or_create(
                    domain=domain,
                    defaults={"org_id": options["org"]},
                )
                if created:
                    self.stdout.write(self.style.SUCCESS(f"Added target: {domain}"))
                else:
                    self.stdout.write(f"Target already exists: {domain}")
                domains = [(domain, target.id)]
            else:
                target = BrandMonitorTarget.objects.filter(domain=domain).first()
                domains = [(domain, target.id if target else None)]

        else:
            raise CommandError("Provide a domain, or use --all to scan all targets")

        headers = _get_vt_headers()
        if "x-apikey" not in headers:
            raise CommandError(
                "VIRUSTOTAL_API_KEY not set. Add it to your .env file or set the environment variable."
            )

        for domain, target_id in domains:
            self.stdout.write(f"\n{'='*60}")
            self.stdout.write(f"Domain: {domain}")
            self.stdout.write(f"{'='*60}")

            try:
                resp = requests.get(
                    f"{VT_API_BASE}/domains/{domain}",
                    headers=headers,
                    timeout=30,
                )

                if resp.status_code == 401:
                    self.stdout.write(self.style.ERROR("Authentication failed. Check your API key."))
                    continue

                if resp.status_code == 404:
                    self.stdout.write(self.style.WARNING(f"Domain '{domain}' not found on VirusTotal"))
                    continue

                if resp.status_code != 200:
                    self.stdout.write(self.style.ERROR(f"API error: {resp.status_code}"))
                    continue

                data = resp.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                if options["json"]:
                    self.stdout.write(json.dumps(stats, indent=2))
                else:
                    try:
                        self._print_report(domain, attributes, stats)
                    except UnicodeEncodeError:
                        self.stdout.write(json.dumps(stats, indent=2))

                if options["save"] and target_id:
                    try:
                        target = BrandMonitorTarget.objects.get(id=target_id)
                        mal_count = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                        susp_count = attributes.get("last_analysis_stats", {}).get("suspicious", 0)
                        rep_score = max(0, min(100, 100 - (mal_count * 15 + susp_count * 5)))
                        stats = {
                            "malicious": mal_count,
                            "suspicious": susp_count,
                            "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                            "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                            "timeout": attributes.get("last_analysis_stats", {}).get("timeout", 0),
                            "total_engines": sum(attributes.get("last_analysis_stats", {}).values()),
                            "reputation": rep_score,
                            "categories": attributes.get("categories", {}),
                            "tags": attributes.get("tags", []),
                            "total_votes": attributes.get("total_votes", {}),
                        }
                        _create_report(target, domain, target.org_id, stats=stats)
                        target.status = "active"
                        target.last_checked_at = timezone.now()
                        target.save(update_fields=["status", "last_checked_at"])
                        self.stdout.write(self.style.SUCCESS("  Report saved to database"))
                    except BrandMonitorTarget.DoesNotExist:
                        self.stdout.write(self.style.WARNING("  Target not found, report not saved"))

            except requests.ConnectionError:
                self.stdout.write(self.style.ERROR(f"  Connection error - check your network"))
            except requests.Timeout:
                self.stdout.write(self.style.ERROR(f"  Request timed out"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))

    def _print_report(self, domain, attributes, stats):
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout = stats.get("timeout", 0)
        total = malicious + suspicious + harmless + undetected + timeout

        self.stdout.write("")
        self.stdout.write(f"  Last Analysis Stats:")
        self.stdout.write(f"    {self._style_count('Malicious', malicious, 'RED')}")
        self.stdout.write(f"    {self._style_count('Suspicious', suspicious, 'YELLOW')}")
        self.stdout.write(f"    Harmless:     {harmless}")
        self.stdout.write(f"    Undetected:   {undetected}")
        self.stdout.write(f"    Timeout:      {timeout}")
        self.stdout.write(f"    ─────────────────────")
        self.stdout.write(f"    Total Engines: {total}")
        self.stdout.write("")

        reputation = attributes.get("reputation", 0)
        votes = attributes.get("total_votes", {})
        self.stdout.write(f"  Reputation Score: {reputation}")
        self.stdout.write(f"  Community Votes:  harmless={votes.get('harmless',0)}  malicious={votes.get('malicious',0)}")

        categories = attributes.get("categories", {})
        if categories:
            self.stdout.write(f"\n  Categories:")
            for engine, cat in sorted(categories.items())[:5]:
                self.stdout.write(f"    {engine}: {cat}")

        tags = attributes.get("tags", [])
        if tags:
            self.stdout.write(f"\n  Tags: {', '.join(tags[:10])}")

        whois = attributes.get("whois", "")
        if whois:
            lines = whois.split("\n")[:6]
            self.stdout.write(f"\n  Whois (first 6 lines):")
            for line in lines:
                self.stdout.write(f"    {line.strip()}")

        if malicious > 0:
            self.stdout.write(
                self.style.ERROR(
                    f"\n  \u26a0 WARNING: {malicious} engine(s) flagged this domain as MALICIOUS"
                )
            )
        elif suspicious > 0:
            self.stdout.write(
                self.style.WARNING(
                    f"\n  \u26a0 CAUTION: {suspicious} engine(s) find this domain suspicious"
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "\n  \u2714 No threats detected - domain appears clean"
                )
            )

        # Show top malicious engines
        results = attributes.get("last_analysis_results", {})
        malicious_results = {
            k: v for k, v in results.items() if v.get("category") == "malicious"
        }
        if malicious_results:
            self.stdout.write(f"\n  Flagged by:")
            for engine, result in sorted(malicious_results.items())[:10]:
                self.stdout.write(f"    {engine}: {result.get('result', 'malicious')}")

    def _style_count(self, label, count, color):
        text = f"{label}: {count}"
        if count > 0:
            return getattr(self.style, color)(text)
        return text


