import os
import json
import logging
import re
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

import requests
from celery import shared_task
from django.utils import timezone
from django.conf import settings

from .models import GitHubRepository, RepoEvent, RepoScan, SurfaceMonitorConfig

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"

# Default headers for GitHub API calls
GITHUB_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "ASMM-SurfaceMonitor/1.0",
}

# If a GITHUB_TOKEN is set in env, use it for higher rate limits
_GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if _GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"token {_GITHUB_TOKEN}"


def _normalize_github_org_login(org_name):
    """Convert a display org name into a likely GitHub organization login."""
    org_name = (org_name or "").strip()
    match = re.search(r"github\.com[:/]([^/\s]+)", org_name)
    if match:
        org_name = match.group(1)
    return re.sub(r"[^a-z0-9-]", "", org_name.lower())


def _search_and_save_repos(org_id, query, discovered_set):
    """Run a single GitHub search query, persist matching repos, and return count."""
    page = 1
    count = 0
    while page <= 2:
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": 100,
            "page": page,
        }
        resp = requests.get(
            f"{GITHUB_API_BASE}/search/repositories",
            headers=GITHUB_HEADERS,
            params=params,
            timeout=15,
        )
        if resp.status_code == 403:
            logger.warning("GitHub API rate limit hit. Stopping pagination.")
            break
        if resp.status_code != 200:
            logger.error("GitHub API error: %s %s", resp.status_code, resp.text[:200])
            break
        data = resp.json()
        items = data.get("items", [])
        if not items:
            break
        for repo_data in items:
            full_name = repo_data.get("full_name", "")
            if full_name in discovered_set:
                continue
            discovered_set.add(full_name)
            owner_data = repo_data.get("owner", {})
            visibility = repo_data.get("visibility", "public")
            repo_obj, created = GitHubRepository.objects.update_or_create(
                full_name=full_name,
                org_id=org_id,
                defaults={
                    "name": repo_data.get("name", ""),
                    "repo_url": repo_data.get("html_url", ""),
                    "owner": owner_data.get("login", ""),
                    "owner_url": owner_data.get("html_url", ""),
                    "description": repo_data.get("description") or "",
                    "visibility": visibility,
                    "language": repo_data.get("language") or "",
                    "default_branch": repo_data.get("default_branch", "main"),
                    "stars": repo_data.get("stargazers_count", 0),
                    "watching_count": repo_data.get("watchers_count", 0),
                    "forks": repo_data.get("forks_count", 0),
                    "open_issues": repo_data.get("open_issues_count", 0),
                    "clone_url": repo_data.get("clone_url", ""),
                    "last_github_updated": repo_data.get("updated_at"),
                    "status": "discovered",
                },
            )
            count += 1
        if len(items) < 100:
            break
        page += 1
    return count, discovered_set


@shared_task(bind=True)
def discover_org_repos(self, org_id="1"):
    """
    Search GitHub for repositories matching this organization's name.
    Runs multiple searches to catch variations:
      - condensed name (e.g. "hackersinfotech" in name)
      - individual words from the original display name (e.g. "Hackers Info Tech" in name)
    Results are merged and persisted with no name-pattern filter.
    """
    try:
        from authentication.models import Organization
        org = Organization.objects.filter(org_id=org_id).first()
        if not org:
            return {"error": f"Organization with org_id={org_id} not found"}
        org_name = org.name
    except Exception as e:
        logger.error("Failed to fetch organization: %s", e)
        return {"error": str(e)}

    github_org = _normalize_github_org_login(org_name)
    if not github_org:
        return {"error": f'Could not derive GitHub organization from "{org_name}"'}

    discovered_set = set()
    total = 0

    try:
        # Search 1: condensed name in repo name (e.g. "hackersinfotech" in name)
        c, discovered_set = _search_and_save_repos(
            org_id, f"{github_org} in:name", discovered_set
        )
        total += c

        # Search 2: original display-name words in repo name
        # (e.g. "Hackers Info Tech" -> matches Hackers_info_tech_project)
        if org_name.strip():
            c, discovered_set = _search_and_save_repos(
                org_id, f'"{org_name}" in:name', discovered_set
            )
            total += c

    except requests.RequestException as e:
        logger.error("GitHub API request failed: %s", e)
        return {"error": str(e), "discovered": total}

    return {
        "org_name": org_name,
        "github_org": github_org,
        "discovered": total,
        "repos": list(discovered_set),
    }


@shared_task(bind=True)
def discover_github_repos(self, config_id=None, keyword=None):
    """
    Search GitHub for repositories matching a keyword and persist results.
    If config_id is provided, uses that config's keyword; otherwise uses
    the passed keyword directly.
    """
    if config_id:
        try:
            config = SurfaceMonitorConfig.objects.get(id=config_id)
            keyword = config.keyword
        except SurfaceMonitorConfig.DoesNotExist:
            return {"error": "Config not found"}
    elif not keyword:
        return {"error": "Either config_id or keyword is required"}

    org_id = config.org_id if config_id else "1"
    discovered = []
    page = 1

    try:
        while page <= 5:  # Limit to 5 pages (500 results max)
            params = {
                "q": keyword,
                "sort": "updated",
                "order": "desc",
                "per_page": 100,
                "page": page,
            }
            resp = requests.get(
                f"{GITHUB_API_BASE}/search/repositories",
                headers=GITHUB_HEADERS,
                params=params,
                timeout=15,
            )

            if resp.status_code == 403:
                logger.warning("GitHub API rate limit hit. Stopping pagination.")
                break
            if resp.status_code != 200:
                logger.error(
                    "GitHub API error: %s %s", resp.status_code, resp.text[:200]
                )
                break

            data = resp.json()
            items = data.get("items", [])
            if not items:
                break

            for repo_data in items:
                owner_data = repo_data.get("owner", {})
                full_name = repo_data.get("full_name", "")
                visibility = repo_data.get("visibility", "public")

                repo_obj, created = GitHubRepository.objects.update_or_create(
                    full_name=full_name,
                    org_id=org_id,
                    defaults={
                        "config": config if config_id else None,
                        "name": repo_data.get("name", ""),
                        "repo_url": repo_data.get("html_url", ""),
                        "owner": owner_data.get("login", ""),
                        "owner_url": owner_data.get("html_url", ""),
                        "description": repo_data.get("description") or "",
                        "visibility": visibility,
                        "language": repo_data.get("language") or "",
                        "default_branch": repo_data.get("default_branch", "main"),
                        "stars": repo_data.get("stargazers_count", 0),
                        "watching_count": repo_data.get("watchers_count", 0),
                        "forks": repo_data.get("forks_count", 0),
                        "open_issues": repo_data.get("open_issues_count", 0),
                        "clone_url": repo_data.get("clone_url", ""),
                        "last_github_updated": repo_data.get("updated_at"),
                        "status": "discovered",
                    },
                )
                discovered.append(
                    {
                        "full_name": full_name,
                        "created": created,
                        "stars": repo_data.get("stargazers_count", 0),
                    }
                )

            if len(items) < 100:
                break
            page += 1

    except requests.RequestException as e:
        logger.error("GitHub API request failed: %s", e)
        return {"error": str(e), "discovered": len(discovered)}

    # Update config's last_run
    if config_id:
        config.updated_at = timezone.now()
        config.save(update_fields=["updated_at"])

    return {
        "keyword": keyword,
        "discovered": len(discovered),
        "repos": discovered,
    }


@shared_task(bind=True)
def scan_repo_with_gitleaks(self, repo_id):
    """
    Clone a GitHub repository and run Gitleaks to detect hardcoded secrets.
    Updates the repository and creates a RepoScan record with findings.
    """
    try:
        repo = GitHubRepository.objects.get(id=repo_id)
    except GitHubRepository.DoesNotExist:
        return {"error": "Repository not found"}

    # Update status
    repo.status = "scanning"
    repo.save(update_fields=["status"])

    scan = RepoScan.objects.create(
        repository=repo,
        status="running",
        started_at=timezone.now(),
        org_id=repo.org_id,
    )

    gitleaks_path = getattr(settings, "GITLEAKS_PATH", None) or shutil.which("gitleaks")
    clone_dir = None

    try:
        # Create a temp directory for cloning
        clone_dir = tempfile.mkdtemp(prefix="surface_monitor_")
        repo_path = Path(clone_dir) / repo.name

        # Clone the repository (shallow clone for speed)
        clone_url = repo.clone_url or f"https://github.com/{repo.full_name}.git"
        logger.info("Cloning %s into %s", clone_url, repo_path)

        clone_result = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if clone_result.returncode != 0:
            raise RuntimeError(
                f"Clone failed: {clone_result.stderr[:500]}"
            )

        repo.status = "cloning"
        repo.save(update_fields=["status"])

        # Count files in the cloned repo
        file_count = 0
        for _, _, files in os.walk(str(repo_path)):
            file_count += len(files)
        scan.scanned_files_count = file_count
        scan.save(update_fields=["scanned_files_count"])

        # Run Gitleaks
        if not gitleaks_path:
            logger.warning("Gitleaks not installed; counting files only.")
            scan.status = "completed"
            scan.completed_at = timezone.now()
            scan.save(update_fields=["status", "completed_at"])
            repo.status = "completed"
            repo.scanned_files_count = file_count
            repo.last_scanned_at = timezone.now()
            repo.save(update_fields=[
                "status", "scanned_files_count", "last_scanned_at"
            ])
            return {"message": "Gitleaks not available; file count only", "files": file_count}

        # Run gitleaks detect
        # Use --report-path - to stream JSON array to stdout.
        # Do NOT use -v here — verbose mode mixes human-readable text with JSON.
        gitleaks_cmd = [
            gitleaks_path,
            "detect",
            "--source", str(repo_path),
            "--report-format", "json",
            "--report-path", "-",
            "--no-git",
        ]
        logger.info("Running gitleaks: %s", " ".join(gitleaks_cmd))

        gitleaks_result = subprocess.run(
            gitleaks_cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout
        )

        raw_output = gitleaks_result.stdout or gitleaks_result.stderr or ""
        scan.raw_output = raw_output[:50000]  # Limit storage

        # Parse findings from JSON array in stdout
        secrets = []
        if gitleaks_result.stdout:
            stdout_trimmed = gitleaks_result.stdout.strip()
            # Gitleaks v8.x outputs a JSON array. Find the first '[' and parse.
            json_start = stdout_trimmed.find('[')
            if json_start >= 0:
                json_str = stdout_trimmed[json_start:]
                try:
                    parsed = json.loads(json_str)
                    if isinstance(parsed, list):
                        secrets = parsed
                    elif isinstance(parsed, dict):
                        secrets = parsed.get("findings", parsed.get("Vulnerabilities", []))
                except json.JSONDecodeError:
                    pass

        # Fallback: check if gitleaks wrote a report file
        if not secrets:
            report_file = repo_path / "report.json"
            if report_file.exists():
                try:
                    with open(report_file, "r") as f:
                        report_data = json.load(f)
                        if isinstance(report_data, list):
                            secrets = report_data
                        elif isinstance(report_data, dict):
                            secrets = report_data.get("findings", report_data.get("Vulnerabilities", []))
                except (json.JSONDecodeError, OSError):
                    pass

        # Detect secrets from exit code if JSON parsing yielded nothing
        # Gitleaks exits with code 1 when leaks are found
        if not secrets and gitleaks_result.returncode != 0:
            # Leaks were detected but couldn't parse JSON — record count from stderr
            leak_match = re.search(r'leaks found: (\d+)', gitleaks_result.stderr or '')
            if leak_match:
                leak_count = int(leak_match.group(1))
                secrets = [{"description": f"{leak_count} leaks detected (unable to parse full JSON output)"}]
                # Store raw stderr as output for debugging
                scan.raw_output = (gitleaks_result.stderr or '')[:50000]

        scan.secrets_found = secrets[:500]  # Limit to 500 findings
        scan.hardcoded_credentials_count = len(secrets)

        # Build a summary
        if secrets:
            rule_counts = {}
            for s in secrets:
                rule = s.get("RuleID", s.get("rule_id", s.get("Description", "Unknown")))
                if isinstance(rule, str):
                    rule_counts[rule] = rule_counts.get(rule, 0) + 1
            if rule_counts:
                summary_parts = [f"{k}: {v}" for k, v in sorted(rule_counts.items(), key=lambda x: -x[1])]
                scan.secrets_summary = "; ".join(summary_parts[:20])
            else:
                scan.secrets_summary = f"{len(secrets)} secret(s) detected"
        else:
            # Check if stderr has a summary line like "leaks found: 0"
            if "leaks found: 0" in (gitleaks_result.stderr or ''):
                scan.secrets_summary = "No secrets found"
            else:
                scan.secrets_summary = "Scan completed"

        scan.status = "completed"
        scan.completed_at = timezone.now()
        scan.save()

        # Update the repository record
        repo.hardcoded_credentials_count = len(secrets)
        repo.scanned_files_count = file_count
        repo.status = "completed"
        repo.last_scanned_at = timezone.now()
        repo.save()

        return {
            "repo": repo.full_name,
            "secrets_found": len(secrets),
            "files_count": file_count,
        }

    except subprocess.TimeoutExpired:
        scan.status = "failed"
        scan.error_message = "Gitleaks scan timed out (300s)"
        scan.completed_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "completed_at"])
        repo.status = "failed"
        repo.save(update_fields=["status"])
        return {"error": "Gitleaks timed out"}

    except Exception as e:
        logger.error("Gitleaks scan failed for %s: %s", repo.full_name, e)
        scan.status = "failed"
        scan.error_message = str(e)[:1000]
        scan.completed_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "completed_at"])
        repo.status = "failed"
        repo.save(update_fields=["status"])
        return {"error": str(e)}

    finally:
        # Cleanup cloned repository
        if clone_dir and os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)


@shared_task(bind=True)
def poll_repo_events(self, repo_id=None, org_id=None):
    """
    Poll GitHub Events API and Actions API for monitored repositories.
    Stores push, create, and action-run events as RepoEvent records.
    If repo_id is provided, polls only that repo; otherwise polls all
    repos for the given org_id (or all repos across all orgs).
    """
    from django.utils import timezone
    import hashlib

    if repo_id:
        repos = GitHubRepository.objects.filter(id=repo_id)
    elif org_id:
        repos = GitHubRepository.objects.filter(org_id=org_id)
    else:
        repos = GitHubRepository.objects.all()

    results = {"repos_checked": 0, "events_stored": 0}
    now = timezone.now()

    for repo in repos:
        results["repos_checked"] += 1

        # --- Poll GitHub Events API ---
        try:
            resp = requests.get(
                f"{GITHUB_API_BASE}/repos/{repo.full_name}/events",
                headers=GITHUB_HEADERS,
                params={"per_page": 10},
                timeout=15,
            )
            if resp.status_code == 200:
                events = resp.json()
                for ev in events:
                    ev_type = ev.get("type", "")
                    ev_id = str(ev.get("id", ""))
                    ev_created = ev.get("created_at", None)

                    # Deduplicate by github_event_id + repo
                    if ev_id and RepoEvent.objects.filter(
                        github_event_id=ev_id, repository=repo
                    ).exists():
                        continue

                    # Map GitHub event type to our event_type
                    actor = ""
                    payload = ev.get("payload", {}) or {}
                    actor_data = ev.get("actor", {}) or {}
                    if isinstance(actor_data, dict):
                        actor = actor_data.get("login", "")

                    if ev_type == "PushEvent":
                        ref = payload.get("ref", "")
                        commits = payload.get("commits", [])
                        commit_msg = commits[0].get("message", "") if commits else ""
                        RepoEvent.objects.create(
                            repository=repo,
                            event_type="push",
                            github_event_id=ev_id,
                            actor=actor,
                            ref=ref,
                            commit_message=commit_msg,
                            commit_count=payload.get("size", 0) or len(commits),
                            event_occurred_at=ev_created or now,
                            org_id=repo.org_id,
                        )
                        results["events_stored"] += 1

                    elif ev_type == "CreateEvent":
                        ref = payload.get("ref", "")
                        ref_type = payload.get("ref_type", "")  # branch, tag, repo
                        RepoEvent.objects.create(
                            repository=repo,
                            event_type="create",
                            github_event_id=ev_id,
                            actor=actor,
                            ref=f"{ref_type}/{ref}" if ref else ref_type,
                            event_occurred_at=ev_created or now,
                            org_id=repo.org_id,
                        )
                        results["events_stored"] += 1

                    elif ev_type == "PublicEvent":
                        RepoEvent.objects.create(
                            repository=repo,
                            event_type="repo_updated",
                            github_event_id=ev_id,
                            actor=actor,
                            commit_message="Repository made public",
                            event_occurred_at=ev_created or now,
                            org_id=repo.org_id,
                        )
                        results["events_stored"] += 1

        except requests.RequestException as e:
            logger.warning("Events API error for %s: %s", repo.full_name, e)

        # --- Poll GitHub Actions API ---
        try:
            resp = requests.get(
                f"{GITHUB_API_BASE}/repos/{repo.full_name}/actions/runs",
                headers=GITHUB_HEADERS,
                params={"per_page": 5},
                timeout=15,
            )
            if resp.status_code == 200:
                runs = resp.json().get("workflow_runs", [])
                for run in runs:
                    run_id = str(run.get("id", ""))
                    if not run_id:
                        continue

                    # Deduplicate
                    if RepoEvent.objects.filter(
                        github_event_id=run_id, repository=repo
                    ).exists():
                        continue

                    conclusion = run.get("conclusion") or ""
                    status = run.get("status", "")
                    run_created = run.get("created_at", None)

                    # Map status+conclusion to event type
                    if status == "completed":
                        if conclusion == "success":
                            ev_type = "action_completed"
                        elif conclusion == "failure":
                            ev_type = "action_failed"
                        elif conclusion == "cancelled":
                            ev_type = "action_cancelled"
                        else:
                            ev_type = "action_completed"
                    elif status == "in_progress":
                        ev_type = "action_in_progress"
                    else:
                        ev_type = "action_pending"

                    actor_data = run.get("actor", {}) or {}
                    actor = actor_data.get("login", "") if isinstance(actor_data, dict) else ""

                    RepoEvent.objects.create(
                        repository=repo,
                        event_type=ev_type,
                        github_event_id=run_id,
                        actor=actor,
                        ref=run.get("head_branch", ""),
                        action_name=run.get("name", run.get("display_title", "")),
                        action_run_url=run.get("html_url", ""),
                        action_conclusion=conclusion,
                        event_occurred_at=run_created or now,
                        org_id=repo.org_id,
                    )
                    results["events_stored"] += 1

        except requests.RequestException as e:
            logger.warning("Actions API error for %s: %s", repo.full_name, e)

        # Update repo's last_github_updated timestamp
        repo.last_github_updated = now
        repo.save(update_fields=["last_github_updated"])

    return results


@shared_task(bind=True)
def run_surface_monitor_discovery(self):
    """
    Periodic task: runs discovery for all active SurfaceMonitorConfigs,
    then optionally triggers Gitleaks scans on newly discovered repos.
    """
    configs = SurfaceMonitorConfig.objects.filter(is_active=True)
    results = []
    for config in configs:
        result = discover_github_repos(config_id=config.id)
        results.append(result)
    return {"configs_processed": len(configs), "results": results}
