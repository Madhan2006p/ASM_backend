from django.db import models


class SurfaceMonitorConfig(models.Model):
    """
    Configuration for surface web monitoring — each entry defines a keyword
    or search query used to discover repositories on GitHub.
    """
    keyword = models.CharField(
        max_length=255,
        help_text="Keyword or search query to discover repositories (e.g. 'stock', 'api-key')"
    )
    is_active = models.BooleanField(default=True)
    interval_minutes = models.IntegerField(
        default=60,
        help_text="How often (in minutes) to re-run discovery for this keyword"
    )
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Surface Monitor Config"
        verbose_name_plural = "Surface Monitor Configs"

    def __str__(self):
        return f"[{'Active' if self.is_active else 'Inactive'}] {self.keyword}"


class GitHubRepository(models.Model):
    """
    Represents a GitHub repository discovered via surface web monitoring.
    """
    VISIBILITY_CHOICES = (
        ('public', 'Public'),
        ('private', 'Private'),
        ('unknown', 'Unknown'),
    )

    STATUS_CHOICES = (
        ('discovered', 'Discovered'),
        ('cloning', 'Cloning'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped'),
    )

    config = models.ForeignKey(
        SurfaceMonitorConfig,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='repositories'
    )
    name = models.CharField(max_length=255)
    full_name = models.CharField(
        max_length=512,
        help_text="Owner/RepoName format (e.g. 'octocat/Hello-World')"
    )
    repo_url = models.URLField(max_length=1024)
    owner = models.CharField(max_length=255)
    owner_url = models.URLField(max_length=1024, blank=True, default='')
    description = models.TextField(blank=True, default='')
    visibility = models.CharField(
        max_length=20, choices=VISIBILITY_CHOICES, default='public'
    )
    language = models.CharField(max_length=100, blank=True, default='')
    default_branch = models.CharField(max_length=100, blank=True, default='main')
    stars = models.IntegerField(default=0)
    watching_count = models.IntegerField(default=0, help_text="Number of users watching/subscribing to this repo")
    forks = models.IntegerField(default=0)
    open_issues = models.IntegerField(default=0)
    last_github_updated = models.DateTimeField(null=True, blank=True)
    clone_url = models.URLField(max_length=1024, blank=True, default='')
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='discovered'
    )
    hardcoded_credentials_count = models.IntegerField(default=0)
    scanned_files_count = models.IntegerField(default=0)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    org_id = models.CharField(max_length=50, default="1")
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-discovered_at"]
        verbose_name = "GitHub Repository"
        verbose_name_plural = "GitHub Repositories"
        unique_together = (("full_name", "org_id"),)

    def __str__(self):
        return self.full_name


class RepoEvent(models.Model):
    """
    Captures GitHub events for a monitored repository: pushes, creates,
    metadata updates, and GitHub Actions workflow runs.
    """
    EVENT_TYPES = (
        ('push', 'Push'),
        ('create', 'Created'),
        ('repo_updated', 'Repo Updated'),
        ('action_pending', 'Action Pending'),
        ('action_in_progress', 'Action In Progress'),
        ('action_completed', 'Action Completed'),
        ('action_failed', 'Action Failed'),
        ('action_cancelled', 'Action Cancelled'),
        ('unknown', 'Unknown'),
    )

    repository = models.ForeignKey(
        GitHubRepository,
        on_delete=models.CASCADE,
        related_name='events'
    )
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES, default='unknown')
    github_event_id = models.CharField(
        max_length=64, blank=True, default='',
        help_text="GitHub event ID or run ID for deduplication"
    )
    actor = models.CharField(
        max_length=255, blank=True, default='',
        help_text="Username that triggered the event"
    )
    ref = models.CharField(
        max_length=255, blank=True, default='',
        help_text="Branch/tag reference (e.g. 'refs/heads/main')"
    )
    commit_message = models.TextField(blank=True, default='')
    commit_count = models.IntegerField(default=0)
    action_name = models.CharField(
        max_length=255, blank=True, default='',
        help_text="GitHub Actions workflow name (for action events)"
    )
    action_run_url = models.URLField(max_length=1024, blank=True, default='')
    action_conclusion = models.CharField(
        max_length=30, blank=True, default='',
        help_text="Conclusion: success, failure, cancelled"
    )
    raw_payload = models.JSONField(default=dict, blank=True)
    org_id = models.CharField(max_length=50, default="1")
    event_occurred_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-event_occurred_at"]
        verbose_name = "Repo Event"
        verbose_name_plural = "Repo Events"
        indexes = [
            models.Index(fields=['repository', 'event_type']),
            models.Index(fields=['org_id', '-event_occurred_at']),
        ]

    def __str__(self):
        return f"[{self.event_type}] {self.repository.full_name}"


class RepoScan(models.Model):
    """
    Tracks each Gitleaks / secret-scan run against a repository.
    """
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )

    repository = models.ForeignKey(
        GitHubRepository,
        on_delete=models.CASCADE,
        related_name='scans'
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='pending'
    )
    secrets_found = models.JSONField(default=list, blank=True)
    secrets_summary = models.TextField(blank=True, default='')
    scanned_files_count = models.IntegerField(default=0)
    hardcoded_credentials_count = models.IntegerField(default=0)
    raw_output = models.TextField(blank=True, default='')
    error_message = models.TextField(blank=True, default='')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    org_id = models.CharField(max_length=50, default="1")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Repo Scan"
        verbose_name_plural = "Repo Scans"

    def __str__(self):
        return f"Scan {self.repository.full_name} - {self.status}"
