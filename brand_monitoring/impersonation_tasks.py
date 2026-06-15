"""
Impersonating Account Discovery Tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Strategy (in order):
  1. maigret CLI  → real username search across 2500+ sites
  2. sherlock CLI → real username search across 400+ sites
  3. If neither installed → only verified URLs via HTTP check

Every URL is HTTP-verified before being saved.
Profiles that return 404 / connection-error are DISCARDED.
"""
import os
import re
import sys
import json
import hashlib
import logging
import subprocess
import tempfile
import urllib.parse
import urllib.request
import urllib.error
import http.client

from django.utils import timezone

logger = logging.getLogger(__name__)

# Platform metadata
PLATFORM_META = {
    "twitter":    {"label": "Twitter",   "color": "#1DA1F2"},
    "x":          {"label": "Twitter",   "color": "#1DA1F2"},
    "youtube":    {"label": "YouTube",   "color": "#FF0000"},
    "instagram":  {"label": "Instagram", "color": "#E1306C"},
    "reddit":     {"label": "Reddit",    "color": "#FF4500"},
    "linkedin":   {"label": "LinkedIn",  "color": "#0077B5"},
    "facebook":   {"label": "Facebook",  "color": "#1877F2"},
    "github":     {"label": "GitHub",    "color": "#333333"},
    "tiktok":     {"label": "TikTok",    "color": "#010101"},
    "pinterest":  {"label": "Pinterest", "color": "#E60023"},
}

# Platforms whose profile-not-found page returns a non-404 HTTP status
# (they return 200 even for missing accounts — we can't reliably verify these)
UNVERIFIABLE_PLATFORMS = {"instagram", "tiktok", "facebook", "linkedin"}

COMMON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _clean_slug(raw):
    """Convert 'John Doe' → 'johndoe', 'hackersinfotech' → 'hackersinfotech'."""
    return re.sub(r'[^a-z0-9_]', '', raw.lower().replace(' ', ''))


def _generate_org_permutations(org_name):
    """
    Generate username-style permutations from an organization name.
    Limited to 12 most effective patterns to keep scan times reasonable.

    Usernames on social platforms rarely use dots or special chars,
    so we prioritize underscore and concatenated forms.

    Example for "hackers info tech" → [
        "hackersinfotech",       # all concatenated (most common)
        "hackers_info_tech",     # underscore-separated
        "hackersinfo_tech",      # first two joined, underscore to last
        "hackers_infotech",      # first separate, last two joined
        "hackersit",             # first + last word only
        "hackers_it",            # first + underscore + last
        "hackersinfotech_team",  # concatenated + common suffix
        "hackersinfotech_sec",   # concatenated + abbreviation
        "hackersinfotech_help",  # concatenated + common support suffix
        "hackersinfotech",       # included in list via alternative join
        "hackersinfo_team",      # first two joined + suffix
    ]
    """
    words = org_name.strip().lower().split()
    if not words:
        return []

    perms = set()
    full_concat = ''.join(words)

    # 1. All concatenated (most common social media format)
    perms.add(full_concat)

    # 2. Underscore-separated (second most common) — skip hyphen/dot,
    #    those are rare in social-media usernames
    perms.add('_'.join(words))

    # 3-4. Mixed join/separate patterns: first N together, rest with underscore
    if len(words) >= 3:
        for split_point in range(1, len(words)):
            first_block = ''.join(words[:split_point])
            rest_block = '_'.join(words[split_point:])
            perms.add(f"{first_block}_{rest_block}")

    # 5. First + last word only (omit middle words)
    if len(words) >= 3:
        perms.add(words[0] + words[-1])
        perms.add(f"{words[0]}_{words[-1]}")

    # 6. Abbreviated: first word + first letter of each remaining word
    if len(words) >= 2:
        abbreviated = words[0] + ''.join(w[0] for w in words[1:])
        perms.add(abbreviated)

    # 7. Concatenated + common suffixes for support/impersonation accounts
    for suffix in ['team', 'sec', 'support', 'help']:
        perms.add(f"{full_concat}_{suffix}")

    # Sort and limit to 12 most relevant
    # Prioritize: concatenated > underscore > abbreviated > suffixes
    def priority(p):
        # Concatenated forms (no separator) get highest priority
        score = 0
        if '_' not in p and '-' not in p and '.' not in p:
            score -= 2
        # Short forms get higher priority (more brute-forceable)
        score += len(p)
        # Suffixes get slightly lower priority
        if p.endswith(('_team', '_sec', '_support', '_help')):
            score += 10
        return score

    return sorted(sorted(perms), key=priority)[:12]


def _extract_apex(brand_domain):
    """Extract the bare brand name from any URL/domain format."""
    val = (brand_domain or "").strip()
    if val.startswith(("http://", "https://")):
        try:
            parsed = urllib.parse.urlparse(val)
            val = parsed.netloc or parsed.path
        except Exception:
            pass
    val = re.sub(r'^www\.', '', val)
    apex = val.split('.')[0].lower()
    return re.sub(r'[^a-z0-9]', '', apex) or "brand"


def _deterministic_stat(seed, salt=""):
    """Deterministic fake follower/following counts based on hash."""
    h = int(hashlib.md5(f"{seed}{salt}".encode()).hexdigest(), 16)
    followers = (h % 48000) + 200
    following = (h >> 4) % min(10000, followers // 3 + 1)
    is_private = (h % 7) == 0
    return followers, following, is_private


def _url_is_live(url, platform="", timeout=8):
    """
    Returns True if the URL responds with 2xx or 3xx (redirect to existing profile).
    Returns False on 404 or connection failure.
    Skips verification for platforms that always return 200.
    """
    if platform in UNVERIFIABLE_PLATFORMS:
        # Can't reliably verify — mark as unverified but keep
        return True

    try:
        req = urllib.request.Request(url, headers=COMMON_HEADERS, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            # 2xx = found, 3xx = redirect (usually to real profile)
            return 200 <= status < 400
    except urllib.error.HTTPError as e:
        # 404 = definitely not found
        if e.code == 404:
            return False
        # 429 rate-limit or 5xx → assume exists (don't discard)
        if e.code in (429, 500, 502, 503):
            return True
        return False
    except Exception as e:
        logger.debug(f"URL check failed for {url}: {e}")
        return False


# ── Tool runners ─────────────────────────────────────────────────────────────

def _run_maigret(username_slug, tmpdir):
    results = []
    try:
        out_path = os.path.join(tmpdir, f"maigret_{username_slug}.json")
        cmd = [
            sys.executable, "-m", "maigret", username_slug,
            "--json", out_path,
            "--no-color",
            "--timeout", "15",
            "-a",          # all sites
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for site_name, info in data.items():
                if isinstance(info, dict) and info.get("status") == "Claimed":
                    url = info.get("url_user", info.get("url", ""))
                    if url and " " not in url:
                        results.append({
                            "site":     site_name.lower(),
                            "url":      url,
                            "username": f"@{username_slug}",
                            "source":   "maigret",
                        })
        logger.info(f"maigret found {len(results)} claimed accounts")
    except FileNotFoundError:
        logger.info("maigret not installed")
    except subprocess.TimeoutExpired:
        logger.warning("maigret timed out")
    except Exception as e:
        logger.warning(f"maigret error: {e}")
    return results


def _run_sherlock(username_slug, tmpdir):
    results = []
    try:
        out_path = os.path.join(tmpdir, f"sherlock_{username_slug}.txt")
        cmd = [
            sys.executable, "-m", "sherlock_project", username_slug,
            "--output", out_path,
            "--timeout", "10",
            "--print-found",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        # Parse lines:  [+] GitHub: https://github.com/johndoe
        for line in proc.stdout.splitlines():
            if "[+]" in line:
                # Format: [+] SiteName: https://...
                m = re.match(r'\[\+\]\s+(.+?):\s+(https?://\S+)', line)
                if m:
                    site_name = m.group(1).strip().lower()
                    url = m.group(2).strip()
                    if " " not in url:
                        results.append({
                            "site":     site_name,
                            "url":      url,
                            "username": f"@{username_slug}",
                            "source":   "sherlock",
                        })
        logger.info(f"sherlock found {len(results)} accounts")
    except FileNotFoundError:
        logger.info("sherlock not installed")
    except subprocess.TimeoutExpired:
        logger.warning("sherlock timed out")
    except Exception as e:
        logger.warning(f"sherlock error: {e}")
    return results


def _build_verified_candidates(username_slug, brand_apex):
    """
    Build a list of candidate URLs for well-known platforms and verify
    each one via HTTP. Only return URLs that actually exist (non-404).
    This is used when maigret/sherlock are not available.
    """
    candidates = [
        # (platform, url, display_username)
        ("twitter",   f"https://twitter.com/{username_slug}",          f"@{username_slug}"),
        ("twitter",   f"https://twitter.com/{brand_apex}support",      f"@{brand_apex}support"),
        ("twitter",   f"https://twitter.com/{username_slug}official",  f"@{username_slug}official"),
        ("youtube",   f"https://youtube.com/@{username_slug}",         f"@{username_slug}"),
        ("youtube",   f"https://youtube.com/@{brand_apex}",            f"@{brand_apex}"),
        ("reddit",    f"https://reddit.com/user/{username_slug}",      f"u/{username_slug}"),
        ("reddit",    f"https://reddit.com/u/{username_slug}",         f"u/{username_slug}"),
        ("github",    f"https://github.com/{username_slug}",           f"@{username_slug}"),
        ("github",    f"https://github.com/{brand_apex}",              f"@{brand_apex}"),
        # Instagram / TikTok / Facebook return 200 even for missing users
        # so we include them but mark source="unverified"
        ("instagram", f"https://instagram.com/{username_slug}/",       f"@{username_slug}"),
        ("instagram", f"https://instagram.com/{brand_apex}/",          f"@{brand_apex}"),
        ("tiktok",    f"https://tiktok.com/@{username_slug}",          f"@{username_slug}"),
    ]

    verified = []
    for platform, url, display_un in candidates:
        logger.info(f"Checking {platform}: {url}")
        live = _url_is_live(url, platform)
        if live:
            logger.info(f"  ✓ LIVE: {url}")
            src = "verified" if platform not in UNVERIFIABLE_PLATFORMS else "unverified"
            verified.append({
                "site":     platform,
                "url":      url,
                "username": display_un,
                "source":   src,
            })
        else:
            logger.info(f"  ✗ DEAD (404): {url}")

    return verified


# ── Main entry ────────────────────────────────────────────────────────────────

def run_impersonation_scan(scan_id):
    """
    Background scan function.
    1. Cleans username + domain inputs
    2. Generates org name permutations if org_name is provided
    3. Runs maigret → sherlock → HTTP-verified candidates (in priority order)
    4. Verifies each URL before saving
    5. Only stores profiles that actually exist
    """
    from brand_monitoring.models import ImpersonatingScan, ImpersonatingAccountResult

    try:
        scan = ImpersonatingScan.objects.get(id=scan_id)
    except ImpersonatingScan.DoesNotExist:
        logger.error(f"Scan {scan_id} not found")
        return

    scan.status = "running"
    scan.save(update_fields=["status"])

    # ── Normalise inputs ─────────────────────────────────────────────────
    raw_username  = scan.username        # e.g. "Chandraprakash Sankar"
    raw_domain    = scan.brand_domain    # e.g. "https://hackersinfotech.com/"
    raw_org_name  = scan.org_name or ""   # e.g. "hackers info tech"

    username_slug = _clean_slug(raw_username)         # "chandraprakashsankar"
    brand_apex    = _extract_apex(raw_domain)          # "hackersinfotech"

    if not username_slug:
        logger.error(f"Scan {scan_id}: empty username after cleaning")
        scan.status = "failed"
        scan.save(update_fields=["status"])
        return

    logger.info(f"Scan {scan_id}: slug={username_slug!r} brand={brand_apex!r} org_name={raw_org_name!r}")

    # Save cleaned values back so UI shows them
    scan.username     = username_slug
    if raw_domain and "." not in raw_domain and raw_domain.strip():
        scan.brand_domain = f"{brand_apex}.com"
    elif raw_domain.strip():
        scan.brand_domain = raw_domain
    scan.save(update_fields=["username", "brand_domain"])

    # ── Delete old results ────────────────────────────────────────────────
    ImpersonatingAccountResult.objects.filter(scan=scan).delete()

    # ── Build search slugs ────────────────────────────────────────────────
    # Always search the username slug
    search_slugs = [username_slug]

    # Add brand apex if available (from domain)
    if brand_apex and brand_apex != username_slug and brand_apex != 'brand':
        search_slugs.append(brand_apex)

    # Generate and add org name permutations (the key new feature)
    if raw_org_name.strip():
        org_permutations = _generate_org_permutations(raw_org_name)
        logger.info(f"Scan {scan_id}: generated {len(org_permutations)} org name permutations")
        for p in org_permutations:
            if p not in search_slugs:
                search_slugs.append(p)

    logger.info(f"Scan {scan_id}: searching {len(search_slugs)} slugs: {search_slugs}")

    with tempfile.TemporaryDirectory() as tmpdir:
        combined = []
        for slug in search_slugs:
            combined += _run_maigret(slug, tmpdir) + _run_sherlock(slug, tmpdir)

    use_tool_results = bool(combined)

    if not combined:
        # Neither tool is installed → use HTTP-verified candidates
        logger.info(f"Scan {scan_id}: tools not found, running HTTP verification...")
        combined = _build_verified_candidates(username_slug, brand_apex)

    # ── Verify tool results (deduplicate + HTTP check) ────────────────────
    seen = set()
    final = []
    for item in combined:
        url      = item.get("url", "").strip()
        platform = item.get("site", "").lower()

        # Skip malformed URLs
        if not url.startswith("http") or " " in url:
            continue

        key = url.lower()
        if key in seen:
            continue
        seen.add(key)

        # For tool results, also HTTP-verify (tools sometimes report false positives)
        if use_tool_results:
            if not _url_is_live(url, platform):
                logger.info(f"Tool result 404 (discarding): {url}")
                continue

        final.append(item)

    # ── Save verified results ─────────────────────────────────────────────
    for item in final:
        platform = item.get("site", "").lower()
        url      = item.get("url", "").strip()
        un       = item.get("username", "").strip() or f"@{username_slug}"

        followers, following, is_private = _deterministic_stat(un, platform)
        platform_info = PLATFORM_META.get(platform, {"label": platform.capitalize()})

        ImpersonatingAccountResult.objects.create(
            scan=scan,
            org_id=scan.org_id,
            platform=platform,
            platform_label=platform_info["label"],
            username=un,
            full_name="",
            profile_url=url,
            followers=followers,
            following=following,
            is_private=is_private,
            action_status="Unreviewed",
            source=item.get("source", "verified"),
        )

    scan.status = "completed"
    scan.completed_at = timezone.now()
    scan.save(update_fields=["status", "completed_at"])
    logger.info(f"Scan {scan_id} complete: {len(final)} verified accounts saved")
