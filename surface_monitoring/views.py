import os
import re
import requests
from datetime import timedelta

from django.utils import timezone

from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from authentication.permissions import (
    IsAuthenticatedAndOrgMember,
    IsOrgAdmin,
    get_user_org_id,
)

from .models import GitHubRepository, RepoEvent, RepoScan, SurfaceMonitorConfig
from .serializers import (
    GitHubRepositorySerializer,
    RepoEventSerializer,
    RepoScanSerializer,
    SurfaceMonitorConfigSerializer,
    SurfaceMonitorDashboardSerializer,
)
from .tasks import discover_github_repos, discover_org_repos, poll_repo_events, scan_repo_with_gitleaks

GITHUB_API_BASE = "https://api.github.com"
GITHUB_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "ASMM-SurfaceMonitor/1.0",
}
_GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if _GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"token {_GITHUB_TOKEN}"


class SurfaceMonitorConfigViewSet(viewsets.ModelViewSet):
    """
    CRUD for surface monitor configurations (keywords to watch).
    """
    serializer_class = SurfaceMonitorConfigSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return SurfaceMonitorConfig.objects.filter(org_id=org_id)

    def perform_create(self, serializer):
        org_id = get_user_org_id(self.request)
        serializer.save(org_id=org_id)

    @action(detail=True, methods=['post'])
    def discover(self, request, pk=None):
        """
        Trigger GitHub repo discovery for this config keyword.
        """
        config = self.get_object()
        task = discover_github_repos.delay(config_id=config.id)
        return Response({
            'task_id': task.id,
            'status': 'discovery_started',
            'keyword': config.keyword,
        }, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=['post'])
    def discover_and_scan(self, request, pk=None):
        """
        Trigger discovery, then scan all repos for this config.
        """
        config = self.get_object()
        task = discover_github_repos.delay(config_id=config.id)
        return Response({
            'task_id': task.id,
            'status': 'discovery_started',
            'keyword': config.keyword,
            'note': 'Repos will be discovered. Use repo-level scan endpoints to trigger secret scanning.',
        }, status=status.HTTP_202_ACCEPTED)


class GitHubRepositoryViewSet(viewsets.ModelViewSet):
    """
    CRUD for discovered GitHub repositories.
    """
    serializer_class = GitHubRepositorySerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        qs = GitHubRepository.objects.filter(org_id=org_id)

        # Filter by config if provided
        config_id = self.request.query_params.get('config')
        if config_id:
            qs = qs.filter(config_id=config_id)
        return qs

    def perform_create(self, serializer):
        org_id = get_user_org_id(self.request)
        serializer.save(org_id=org_id)

    @action(detail=True, methods=['post'])
    def scan(self, request, pk=None):
        """
        Trigger a Gitleaks scan on this repository.
        """
        repo = self.get_object()
        task = scan_repo_with_gitleaks.delay(repo_id=repo.id)
        return Response({
            'task_id': task.id,
            'repo': repo.full_name,
            'status': 'scan_queued',
        }, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['post'])
    def scan_all(self, request):
        """
        Trigger Gitleaks scan on all discovered repos.
        """
        org_id = get_user_org_id(self.request)
        repos = GitHubRepository.objects.filter(org_id=org_id)
        task_ids = []
        for repo in repos:
            task = scan_repo_with_gitleaks.delay(repo_id=repo.id)
            task_ids.append({'repo': repo.full_name, 'task_id': task.id})
        return Response({
            'tasks': task_ids,
            'count': len(task_ids),
            'status': 'batch_scan_queued',
        }, status=status.HTTP_202_ACCEPTED)

    @staticmethod
    def _normalize_repo_full_name(raw):
        """
        Accept various GitHub repo formats and return 'owner/repo'.
        Supports:
          - 'octocat/Hello-World'
          - 'https://github.com/octocat/Hello-World'
          - 'https://github.com/octocat/Hello-World.git'
          - 'git@github.com:octocat/Hello-World.git'
        """
        raw = raw.strip()
        # Already owner/repo format
        if '/' in raw and 'github.com' not in raw and 'github.com:' not in raw:
            # Strip trailing slash and .git extension
            result = raw.rstrip('/')
            if result.endswith('.git'):
                result = result[:-4]
            return result
        # Full HTTPS URL: https://github.com/owner/repo[.git]
        m = re.search(r'github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$', raw)
        if m:
            return m.group(1)
        # SSH URL: git@github.com:owner/repo.git
        m = re.search(r'git@github\.com:([^/]+/[^/]+?)(?:\.git)?/?$', raw)
        if m:
            return m.group(1)
        return raw

    @action(detail=False, methods=['post'])
    def add_repo(self, request):
        """
        Manually add a GitHub repository by full_name (e.g. 'octocat/Hello-World').
        Also accepts full URLs like 'https://github.com/octocat/Hello-World'.
        Fetches repository metadata from the GitHub API.
        """
        raw = request.data.get('full_name', '').strip()
        if not raw:
            return Response(
                {'error': 'full_name is required (e.g. "octocat/Hello-World")'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        full_name = self._normalize_repo_full_name(raw)

        org_id = get_user_org_id(self.request)

        # Check if already exists
        existing = GitHubRepository.objects.filter(full_name=full_name, org_id=org_id).first()
        if existing:
            serializer = self.get_serializer(existing)
            return Response({
                'message': 'Repository already exists',
                'repo': serializer.data,
            })

        # Fetch from GitHub API
        try:
            resp = requests.get(
                f"{GITHUB_API_BASE}/repos/{full_name}",
                headers=GITHUB_HEADERS,
                timeout=15,
            )
            if resp.status_code == 403:
                return Response(
                    {'error': 'GitHub API rate limit hit. Set GITHUB_TOKEN env var for higher limits.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            if resp.status_code == 404:
                return Response(
                    {'error': f'Repository "{full_name}" not found on GitHub.'},
                    status=status.HTTP_404_NOT_FOUND,
                )
            if resp.status_code != 200:
                return Response(
                    {'error': f'GitHub API error: {resp.status_code}'},
                    status=status.HTTP_502_BAD_GATEWAY,
                )

            repo_data = resp.json()
            owner_data = repo_data.get('owner', {})
            visibility = repo_data.get('visibility', 'public')

            repo = GitHubRepository.objects.create(
                name=repo_data.get('name', ''),
                full_name=repo_data.get('full_name', ''),
                repo_url=repo_data.get('html_url', ''),
                owner=owner_data.get('login', ''),
                owner_url=owner_data.get('html_url', ''),
                description=repo_data.get('description') or '',
                visibility=visibility,
                language=repo_data.get('language') or '',
                default_branch=repo_data.get('default_branch', 'main'),
                stars=repo_data.get('stargazers_count', 0),
                watching_count=repo_data.get('watchers_count', 0),
                forks=repo_data.get('forks_count', 0),
                open_issues=repo_data.get('open_issues_count', 0),
                clone_url=repo_data.get('clone_url', ''),
                last_github_updated=repo_data.get('updated_at'),
                status='discovered',
                org_id=org_id,
            )

            serializer = self.get_serializer(repo)
            return Response({
                'message': f'Repository "{full_name}" added successfully',
                'repo': serializer.data,
            }, status=status.HTTP_201_CREATED)

        except requests.RequestException as e:
            return Response(
                {'error': f'Failed to fetch repository: {str(e)}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

    @action(detail=True, methods=['post'])
    def poll_events(self, request, pk=None):
        """
        Trigger event polling for a single repository.
        """
        repo = self.get_object()
        task = poll_repo_events.delay(repo_id=repo.id)
        return Response({
            'task_id': task.id,
            'repo': repo.full_name,
            'status': 'polling_started',
        }, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['post'])
    def discover_by_org(self, request):
        """
        Discover GitHub repositories belonging to the current organization.
        Searches GitHub using the `org:` qualifier and saves any found repos.
        Uses update_or_create so existing repos are updated, never duplicated.
        No data is ever deleted — this is purely additive.
        """
        org_id = get_user_org_id(request)
        from authentication.models import Organization
        org = Organization.objects.filter(org_id=org_id).first()
        org_name = org.name if org else "Unknown"

        try:
            result = discover_org_repos(org_id=org_id)
            return Response({
                'org_name': org_name,
                'status': 'org_discovery_completed',
                'repos_cleared': 0,
                'result': result,
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'org_name': org_name,
                'status': 'org_discovery_failed',
                'error': str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Return aggregate dashboard stats for surface monitoring.
        """
        org_id = get_user_org_id(self.request)
        repos = GitHubRepository.objects.filter(org_id=org_id)
        scans = RepoScan.objects.filter(org_id=org_id)
        configs = SurfaceMonitorConfig.objects.filter(org_id=org_id)
        events = RepoEvent.objects.filter(org_id=org_id)

        total_secrets = sum(r.hardcoded_credentials_count for r in repos)

        # Count by visibility
        visibility_counts = {}
        for r in repos:
            v = r.visibility or 'unknown'
            visibility_counts[v] = visibility_counts.get(v, 0) + 1

        # Count by language
        language_counts = {}
        for r in repos:
            lang = r.language or 'Unknown'
            language_counts[lang] = language_counts.get(lang, 0) + 1

        # Event breakdown (last 7 days)
        recent = events.filter(event_occurred_at__gte=timezone.now() - timedelta(days=7))

        # Get org name
        org_name = "Unknown"
        try:
            from authentication.models import Organization
            org = Organization.objects.filter(org_id=org_id).first()
            if org:
                org_name = org.name
        except Exception:
            pass

        total_watching = sum(r.watching_count for r in repos if r.watching_count)

        serializer = SurfaceMonitorDashboardSerializer(data={
            'total_repos': repos.count(),
            'total_scans': scans.count(),
            'total_secrets_found': total_secrets,
            'active_keywords': configs.filter(is_active=True).count(),
            'org_name': org_name,
            'total_watching': total_watching,
            'recent_events': recent.count(),
            'recent_pushes': recent.filter(event_type='push').count(),
            'recent_creates': recent.filter(event_type='create').count(),
            'recent_updates': recent.filter(event_type='repo_updated').count(),
            'recent_action_success': recent.filter(event_type='action_completed').count(),
            'recent_action_failed': recent.filter(event_type='action_failed').count(),
            'latest_events': RepoEventSerializer(
                recent.order_by('-event_occurred_at')[:5],
                many=True
            ).data,
            'repos_by_visibility': visibility_counts,
            'repos_by_language': language_counts,
        })
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


class RepoEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only view of GitHub repo events (pushes, creates, actions).
    """
    serializer_class = RepoEventSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        qs = RepoEvent.objects.filter(org_id=org_id).select_related('repository')

        # Filter by repo
        repo_id = self.request.query_params.get('repo')
        if repo_id:
            qs = qs.filter(repository_id=repo_id)

        # Filter by event type
        ev_type = self.request.query_params.get('type')
        if ev_type:
            qs = qs.filter(event_type=ev_type)

        return qs


class RepoScanViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only view of repo scan results.
    """
    serializer_class = RepoScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember]

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        qs = RepoScan.objects.filter(org_id=org_id).select_related('repository')

        # Filter by repo if provided
        repo_id = self.request.query_params.get('repo')
        if repo_id:
            qs = qs.filter(repository_id=repo_id)
        return qs
