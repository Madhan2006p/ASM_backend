"""
OWASP Scanner - Asset Discovery & Web Crawler
==============================================
Phase 1: Crawls the target and builds a complete asset inventory.
Discoveries: URLs, API endpoints, parameters, forms, JS files,
hidden dirs, robots.txt, sitemap.xml, auth pages.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import (
    urljoin, urlparse, urlunparse, urlencode, parse_qs, parse_qsl
)

import httpx
from bs4 import BeautifulSoup

from ..core import (
    AssetInfo, ScanTarget, RateLimiter, make_http_client
)

logger = logging.getLogger('scanner.crawler')


# ─── Auth page patterns ────────────────────────────────────────────────────
AUTH_PATTERNS = re.compile(
    r'(login|signin|sign.in|auth|logout|register|signup|password|forgot|reset|'  
    r'account|admin|dashboard|portal|oauth|sso)',
    re.IGNORECASE
)

# ─── API endpoint patterns ─────────────────────────────────────────────────
API_PATTERNS = re.compile(
    r'/api/|/v[0-9]+/|/rest/|/graphql|/gql|/rpc|/service|/ws/|/socket',
    re.IGNORECASE
)

# ─── Interesting file extensions ───────────────────────────────────────────
INTERESTING_EXT = {
    '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
    '.json', '.xml', '.yaml', '.yml', '.env', '.bak',
    '.sql', '.txt', '.log', '.conf', '.config',
    '.git', '.svn', '.htaccess',
}

# ─── JS source URL patterns ────────────────────────────────────────────────
JS_URL_PATTERN = re.compile(
    r'(?:fetch|axios|http|https|XMLHttpRequest|url|href|src|action|endpoint)'
    r'[^\w].*?["\x27](/[\w/._\-?&=#%]+)["\x27]',
    re.IGNORECASE
)
JS_API_PATTERN = re.compile(
    r'["\x27](/(?:api|v[0-9]+|rest|graphql)/[\w/._\-?&=#%]*)["\x27]',
    re.IGNORECASE
)


class WebCrawler:
    """
    Async BFS web crawler that discovers all assets on the target.
    Respects scope (same-domain only) and depth limits.
    """

    def __init__(
        self,
        target: ScanTarget,
        config: Dict[str, Any],
    ):
        self.target = target
        self.config = config
        self.perf = config.get('performance', {})
        self.disc = config.get('discovery', {})

        self.max_urls = int(self.perf.get('max_urls_to_crawl', 500))
        self.max_depth = int(self.perf.get('max_depth', 5))
        self.rate_limiter = RateLimiter(
            delay=float(self.perf.get('rate_limit_delay', 0.5))
        )

        # Visited tracking
        self._visited: Set[str] = set()
        self._queue: deque = deque()
        self._assets: List[AssetInfo] = []
        self._asset_urls: Set[str] = set()

        # Parsed target
        self._parsed = urlparse(target.url)
        self._base_domain = self._parsed.netloc

    async def crawl(self) -> List[AssetInfo]:
        """Run the full crawl and return discovered assets."""
        async with make_http_client(self.config) as client:
            self.client = client

            # Seed
            self._queue.append((self.target.url, 0))

            # Special resources
            await self._check_robots_txt()
            await self._check_sitemap()
            await self._check_security_txt()
            await self._check_wellknown()

            # BFS crawl
            while self._queue and len(self._visited) < self.max_urls:
                batch = []
                for _ in range(min(10, len(self._queue))):
                    if self._queue:
                        batch.append(self._queue.popleft())

                tasks = [self._crawl_url(url, depth) for url, depth in batch]
                await asyncio.gather(*tasks, return_exceptions=True)

        logger.info('Crawl complete. Discovered %d assets.', len(self._assets))
        return self._assets

    async def _crawl_url(self, url: str, depth: int) -> None:
        url = self._normalize_url(url)
        if not url or url in self._visited:
            return
        if not self._in_scope(url):
            return

        self._visited.add(url)
        await self.rate_limiter.acquire()

        try:
            resp = await asyncio.wait_for(self.client.get(url), timeout=3.0)
        except Exception as e:
            logger.debug('Crawl error %s: %s', url, e)
            return

        content_type = resp.headers.get('content-type', '')
        self._register_asset(url, 'URL', resp.status_code, content_type, dict(resp.headers))

        if 'text/html' in content_type and depth < self.max_depth:
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = self._extract_links(soup, url)
            forms = self._extract_forms(soup, url)
            if forms:
                self._register_asset(url, 'FORM', resp.status_code, content_type, {},
                                     forms=forms)

            if self.disc.get('crawl_js', True):
                await self._process_js_links(soup, url, depth)

            for link in links:
                if link not in self._visited:
                    self._queue.append((link, depth + 1))

        elif 'javascript' in content_type or url.endswith('.js'):
            self._register_asset(url, 'JS_FILE', resp.status_code, content_type, {})
            js_urls = self._extract_js_urls(resp.text, url)
            for jurl in js_urls:
                if jurl not in self._visited:
                    self._queue.append((jurl, depth + 1))

    async def _check_robots_txt(self) -> None:
        robots_url = urljoin(self.target.url, '/robots.txt')
        try:
            resp = await self.client.get(robots_url)
            if resp.status_code == 200 and 'text' in resp.headers.get('content-type', ''):
                self._register_asset(robots_url, 'ROBOTS', 200, 'text/plain', {})
                # Parse disallowed paths - they may contain sensitive areas
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(('disallow:', 'allow:')):
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and path != '/':
                                full_url = urljoin(self.target.url, path)
                                if full_url not in self._visited:
                                    self._queue.append((full_url, 0))
        except Exception as e:
            logger.debug('robots.txt error: %s', e)

    async def _check_sitemap(self) -> None:
        for sitemap_path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemaps.xml']:
            sitemap_url = urljoin(self.target.url, sitemap_path)
            try:
                resp = await self.client.get(sitemap_url)
                if resp.status_code == 200:
                    self._register_asset(sitemap_url, 'SITEMAP', 200, 'application/xml', {})
                    urls = re.findall(r'<loc>([^<]+)</loc>', resp.text)
                    for u in urls[:100]:  # limit from sitemap
                        if self._in_scope(u) and u not in self._visited:
                            self._queue.append((u, 1))
                    break
            except Exception:
                pass

    async def _check_security_txt(self) -> None:
        for path in ['/.well-known/security.txt', '/security.txt']:
            try:
                resp = await self.client.get(urljoin(self.target.url, path))
                if resp.status_code == 200:
                    self._register_asset(urljoin(self.target.url, path), 'URL', 200, 'text/plain', {})
                    break
            except Exception:
                pass

    async def _check_wellknown(self) -> None:
        paths = ['/.well-known/', '/.git/HEAD', '/.env', '/config.php',
                 '/wp-login.php', '/admin/', '/administrator/', '/phpmyadmin/',
                 '/swagger.json', '/swagger.yaml', '/openapi.json', '/api-docs',
                 '/actuator', '/actuator/health', '/metrics', '/status',
                 '/_cat/indices', '/console', '/manager/html']
        tasks = [self._probe_path(p) for p in paths]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_path(self, path: str) -> None:
        url = urljoin(self.target.url, path)
        await self.rate_limiter.acquire()
        try:
            resp = await self.client.get(url)
            if resp.status_code in (200, 301, 302, 403):
                atype = self._classify_url(url)
                self._register_asset(url, atype, resp.status_code,
                                     resp.headers.get('content-type', ''), dict(resp.headers))
        except Exception:
            pass

    async def _process_js_links(self, soup: BeautifulSoup, base_url: str, depth: int) -> None:
        script_tags = soup.find_all('script', src=True)
        for script in script_tags:
            src = script.get('src', '')
            if src:
                js_url = urljoin(base_url, src)
                if self._in_scope(js_url) and js_url not in self._visited:
                    self._register_asset(js_url, 'JS_FILE', 0, 'text/javascript', {})
                    if depth < self.max_depth:
                        await self.rate_limiter.acquire()
                        try:
                            resp = await self.client.get(js_url)
                            js_urls = self._extract_js_urls(resp.text, js_url)
                            for jurl in js_urls:
                                if jurl not in self._visited:
                                    self._queue.append((jurl, depth + 1))
                        except Exception:
                            pass

        # Inline scripts
        for script in soup.find_all('script', src=False):
            if script.string:
                js_urls = self._extract_js_urls(script.string, base_url)
                for jurl in js_urls:
                    if jurl not in self._visited and self._in_scope(jurl):
                        self._queue.append((jurl, depth + 1))

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        links = []
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href', '')
            full = urljoin(base_url, href)
            normalized = self._normalize_url(full)
            if normalized and self._in_scope(normalized):
                links.append(normalized)

        for tag in soup.find_all(['form'], action=True):
            action = tag.get('action', '')
            if action:
                full = urljoin(base_url, action)
                links.append(self._normalize_url(full))

        return list(set(links))

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = (form.get('method', 'get') or 'get').upper()
            action_url = urljoin(base_url, action) if action else base_url
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_type = inp.get('type', 'text')
                inp_name = inp.get('name', '')
                if inp_name:
                    inputs.append({'name': inp_name, 'type': inp_type,
                                   'value': inp.get('value', '')})
            forms.append({'action': action_url, 'method': method, 'inputs': inputs})
        return forms

    def _extract_js_urls(self, js_content: str, base_url: str) -> List[str]:
        found = set()
        for pattern in [JS_URL_PATTERN, JS_API_PATTERN]:
            for match in pattern.finditer(js_content):
                path = match.group(1)
                if path.startswith('/'):
                    full = urljoin(self.target.url, path)
                    if self._in_scope(full):
                        found.add(self._normalize_url(full))
        return list(found)

    def _in_scope(self, url: str) -> bool:
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        return parsed.netloc == self._base_domain

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        # Remove fragments
        clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, parsed.query, ''))
        return clean.rstrip('/')

    def _classify_url(self, url: str) -> str:
        path = urlparse(url).path.lower()
        if API_PATTERNS.search(path):
            return 'API'
        if AUTH_PATTERNS.search(path):
            return 'AUTH_PAGE'
        parsed_path = urlparse(url).path
        for ext in INTERESTING_EXT:
            if parsed_path.endswith(ext):
                return 'URL'
        if parsed_path.endswith('/'):
            return 'DIR'
        return 'URL'

    def _register_asset(
        self, url: str, asset_type: str,
        status_code: int = 0, content_type: str = '',
        headers: Optional[Dict] = None,
        forms: Optional[List] = None,
    ) -> None:
        if url in self._asset_urls:
            return
        self._asset_urls.add(url)

        # Upgrade type based on url content
        atype = asset_type
        if asset_type == 'URL':
            atype = self._classify_url(url)

        # Extract params from URL
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        asset = AssetInfo(
            url=url,
            asset_type=atype,
            status_code=status_code,
            content_type=content_type,
            headers=headers or {},
            params={k: [v] for k, v in params.items()},
            forms=forms or [],
        )
        self._assets.append(asset)
        logger.debug('Asset discovered: [%s] %s', atype, url)
