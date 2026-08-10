#!/usr/bin/env python3
"""
End-to-end test for the Surface Web Monitoring pipeline.

Tests:
1. Creating a SurfaceMonitorConfig
2. Discovering GitHub repos via the GitHub Search API
3. Running Gitleaks secret scanning on a discovered repo
4. Verifying scan results are stored in the database

This bypasses Celery and calls functions synchronously.
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
django.setup()

from django.conf import settings
from surface_monitoring.models import SurfaceMonitorConfig, GitHubRepository, RepoScan
from surface_monitoring.tasks import discover_github_repos, scan_repo_with_gitleaks

# Verify Gitleaks is installed
gitleaks_path = getattr(settings, "GITLEAKS_PATH", None)
print(f"=" * 60)
print(f"  SURFACE WEB MONITORING - PIPELINE TEST")
print(f"=" * 60)

print(f"\n[1] Checking Gitleaks installation...")
if gitleaks_path:
    print(f"    ✓ GITLEAKS_PATH = {gitleaks_path}")
else:
    import shutil
    gitleaks_path = shutil.which("gitleaks")
    if gitleaks_path:
        print(f"    ✓ Gitleaks found via PATH: {gitleaks_path}")
    else:
        print(f"    ✗ Gitleaks not found! Please install it first.")
        sys.exit(1)

# Run gitleaks version
import subprocess
result = subprocess.run([gitleaks_path, "--version"], capture_output=True, text=True)
print(f"    Version: {result.stdout.strip() or result.stderr.strip()}")

# Create a monitor config
print(f"\n[2] Creating SurfaceMonitorConfig for keyword 'test-repo-secrets'...")
config, created = SurfaceMonitorConfig.objects.get_or_create(
    keyword="test-repo-secrets",
    defaults={"is_active": True, "interval_minutes": 60, "org_id": "1"}
)
config.is_active = True
config.save()
print(f"    ✓ Config ID: {config.id}, Keyword: '{config.keyword}'")

# Step 1: Discover repos using GitHub Search API
print(f"\n[3] Running GitHub repo discovery (keyword='gitleaks test')...")
discover_result = discover_github_repos(keyword="gitleaks test")
print(f"    Result: {discover_result}")

repos = GitHubRepository.objects.filter(config=config)
if not repos.exists():
    # Fallback: discover with a broader keyword
    print(f"\n    No repos found for config. Trying broader keyword 'python project'...")
    discover_result = discover_github_repos(keyword="python project")
    print(f"    Result: {discover_result}")
    repos = GitHubRepository.objects.all()

print(f"\n[4] Discovered repositories:")
for repo in GitHubRepository.objects.all().order_by("-stars")[:10]:
    print(f"    - {repo.full_name:50s} ⭐{repo.stars:5d}  {repo.language or 'N/A':15s} [{repo.visibility}]")

total_repos = GitHubRepository.objects.count()
print(f"\n    Total repos discovered: {total_repos}")

if total_repos == 0:
    print(f"\n    ⚠ No repos discovered. GitHub API may be rate-limited without a token.")
    print(f"      Set GITHUB_TOKEN environment variable for higher limits.")
else:
    # Step 2: Pick the most popular repo and scan with Gitleaks
    target_repo = GitHubRepository.objects.order_by("-stars").first()
    print(f"\n[5] Running Gitleaks scan on: {target_repo.full_name}")
    print(f"    Clone URL: {target_repo.clone_url or 'N/A'}")
    print(f"    Stars: {target_repo.stars}, Forks: {target_repo.forks}, Language: {target_repo.language}")

    scan_result = scan_repo_with_gitleaks(repo_id=target_repo.id)
    print(f"\n    Scan result: {scan_result}")

    # Refresh from DB
    target_repo.refresh_from_db()

    # Step 3: Verify database results
    print(f"\n[6] Database verification:")
    scans = RepoScan.objects.filter(repository=target_repo).order_by("-created_at")
    print(f"    Number of scans: {scans.count()}")

    if scans.exists():
        scan = scans.first()
        print(f"    Scan status: {scan.status}")
        print(f"    Secrets found: {scan.hardcoded_credentials_count}")
        print(f"    Files scanned: {scan.scanned_files_count}")
        print(f"    Summary: {scan.secrets_summary or 'N/A'}")
        print(f"    Started: {scan.started_at}")
        print(f"    Completed: {scan.completed_at}")

        if scan.status == "completed":
            print(f"\n    ✓ Pipeline completed successfully!")
        elif scan.status == "failed":
            print(f"\n    ✗ Scan failed: {scan.error_message}")
        else:
            print(f"\n    ? Scan status: {scan.status}")

    # Display repo-level results
    print(f"\n[7] Repository-level results:")
    print(f"    Repo: {target_repo.full_name}")
    print(f"    Status: {target_repo.status}")
    print(f"    Hardcoded credentials count: {target_repo.hardcoded_credentials_count}")
    print(f"    Scanned files count: {target_repo.scanned_files_count}")
    print(f"    Last scanned: {target_repo.last_scanned_at}")

print(f"\n" + "=" * 60)
print(f"  TEST COMPLETE")
print(f"=" * 60)
print(f"\nGitleaks path: {gitleaks_path}")
print(f"Configs: {SurfaceMonitorConfig.objects.count()}")
print(f"Repos: {GitHubRepository.objects.count()}")
print(f"Scans: {RepoScan.objects.count()}")
