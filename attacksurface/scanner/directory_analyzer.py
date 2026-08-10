"""
Content-based directory / file discovery analysis engine.

This module replaces the naive "HTTP 200 == Exposed" classification with a
multi-factor, content-aware analysis:

1. The HTTP status code is only the starting point.
2. The Content-Type is parsed and used to pick the right inspection strategy
   (HTML, XML, JSON, plain text, archives, images, ...).
3. The response body is inspected for sensitive content markers (credentials,
   private keys, database dumps, directory listings, config/environment files,
   source code, logs, internal paths, debug info, ...).
4. Path heuristics are combined with content evidence to assign a *category*.
5. A semantic *access status* (Public / Protected / Restricted / Exposed /
   Not Found / Forbidden / Redirected / Error / Unreachable) is derived from
   status + content, NOT from status alone.
6. A *risk level* (Low / Medium / High / Critical) is computed from multiple
   factors: content sensitivity, authentication requirements, misconfiguration,
   information disclosure, exploitability and business impact.

OWASP-aligned checks (Information Disclosure & Security Misconfiguration):
- CWE-200   exposure of sensitive information
- CWE-215   exposure of debug / development information
- CWE-530   exposure of backup files
- CWE-538   exposure of files/directories through the web server
- CWE-548   exposure of directory listing
- CWE-552   files accessible to external parties
- CWE-798   use of hard-coded credentials (secrets exposed in files)
"""

import hashlib
import json
import re

# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

CATEGORY_DEFAULT = "Public File"
CATEGORY_STATIC_ASSET = "Static Asset"
CATEGORY_DIRECTORY_LISTING = "Directory Listing"
CATEGORY_BACKUP_FILE = "Backup File"
CATEGORY_CONFIG_FILE = "Config File"
CATEGORY_ENVIRONMENT_FILE = "Environment File"
CATEGORY_CREDENTIALS = "Credentials / Secrets"
CATEGORY_DATABASE_DUMP = "Database Dump"
CATEGORY_SOURCE_CODE = "Source Code"
CATEGORY_LOG_FILE = "Log File"
CATEGORY_VCS_METADATA = "VCS Metadata"
CATEGORY_INTERNAL_PATH = "Internal Path"
CATEGORY_PRIVATE_DOCUMENT = "Private Document"
CATEGORY_SENSITIVE_METADATA = "Sensitive Metadata"
CATEGORY_ADMIN_PANEL = "Admin Panel"
CATEGORY_LOGIN_PAGE = "Login Page"
CATEGORY_API_ENDPOINT = "API Endpoint"
CATEGORY_PUBLIC_FILE = CATEGORY_DEFAULT
CATEGORY_NOT_FOUND = "Not Found"
CATEGORY_REDIRECT = "Redirect"
CATEGORY_ERROR = "Error"

# Categories whose mere presence (with a 2xx response) constitutes an exposure.
EXPOSED_BY_NATURE = frozenset(
    {
        CATEGORY_DIRECTORY_LISTING,
        CATEGORY_BACKUP_FILE,
        CATEGORY_CONFIG_FILE,
        CATEGORY_ENVIRONMENT_FILE,
        CATEGORY_CREDENTIALS,
        CATEGORY_DATABASE_DUMP,
        CATEGORY_SOURCE_CODE,
        CATEGORY_LOG_FILE,
        CATEGORY_VCS_METADATA,
        CATEGORY_INTERNAL_PATH,
        CATEGORY_PRIVATE_DOCUMENT,
        CATEGORY_SENSITIVE_METADATA,
    }
)

# Categories that the UI groups under "Sensitive" for stats/filters.
SENSITIVE_CATEGORIES = frozenset(
    {
        CATEGORY_DIRECTORY_LISTING,
        CATEGORY_BACKUP_FILE,
        CATEGORY_CONFIG_FILE,
        CATEGORY_ENVIRONMENT_FILE,
        CATEGORY_CREDENTIALS,
        CATEGORY_DATABASE_DUMP,
        CATEGORY_SOURCE_CODE,
        CATEGORY_LOG_FILE,
        CATEGORY_VCS_METADATA,
        CATEGORY_INTERNAL_PATH,
        CATEGORY_PRIVATE_DOCUMENT,
        CATEGORY_SENSITIVE_METADATA,
    }
)

# ---------------------------------------------------------------------------
# Access statuses
# ---------------------------------------------------------------------------

STATUS_PUBLIC = "Public"
STATUS_PROTECTED = "Protected"
STATUS_RESTRICTED = "Restricted"
STATUS_EXPOSED = "Exposed"
STATUS_NOT_FOUND = "Not Found"
STATUS_FORBIDDEN = "Forbidden"
STATUS_REDIRECTED = "Redirected"
STATUS_ERROR = "Error"
STATUS_UNREACHABLE = "Unreachable"

# ---------------------------------------------------------------------------
# Content-type helpers
# ---------------------------------------------------------------------------

_TEXTUAL_MIME_PREFIXES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/xhtml",
    "application/yaml",
    "application/x-yaml",
    "application/x-www-form-urlencoded",
    "application/x-perl",
    "application/x-php",
    "application/x-python",
    "application/x-sh",
    "application/x-shellscript",
)

# Note: 'octet-stream' is deliberately NOT an archive type — it is the generic
# binary fallback and is frequently used for text files such as .env.
_ARCHIVE_MIME_PATTERNS = re.compile(
    r"(zip|gzip|x-gzip|tar|x-tar|rar|x-rar|x-7z|x-7z-compressed|"
    r"x-bzip|x-bzip2|x-compress|x-lzma|x-xz|x-zip-compressed|"
    r"vnd\.ms-office|msword|pdf|vnd\.openxmlformats)"
)


def normalize_content_type(content_type):
    """Return (mime_type, kind) where kind is one of html/xml/json/text/..."""
    ct = (content_type or "").split(";")[0].strip().lower()
    if not ct:
        return ct, "binary"
    if "html" in ct:
        return ct, "html"
    if "xml" in ct:
        return ct, "xml"
    if ct.endswith("json") or "json" in ct:
        return ct, "json"
    if ct.startswith("text/"):
        return ct, "text"
    if ct.startswith("image/"):
        return ct, "image"
    if ct.startswith("font/") or ct in ("application/font-woff", "application/font-woff2",
                                        "application/vnd.ms-fontobject", "application/x-font-ttf"):
        return ct, "font"
    if _ARCHIVE_MIME_PATTERNS.search(ct):
        return ct, "archive"
    if ct.startswith("audio/"):
        return ct, "audio"
    if ct.startswith("video/"):
        return ct, "video"
    if ct.startswith("application/"):
        return ct, "binary"
    return ct, "binary"


def _decode_body(body_bytes):
    """Best-effort decode of raw bytes to text."""
    if not body_bytes:
        return ""
    for encoding in ("utf-8", "latin-1"):
        try:
            return body_bytes.decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            continue
    try:
        return body_bytes.decode("utf-8", errors="replace")
    except AttributeError:
        return ""


def extract_text(body_bytes, mime_kind):
    """Return (lowercased_text, title) suitable for content matching."""
    text = _decode_body(body_bytes)
    title = ""
    if mime_kind == "html":
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if m:
            title = re.sub(r"<[^>]+>", "", m.group(1)).strip()[:200]
    return text.lower(), title


def sanitize_preview(body_bytes, limit=300):
    """Produce a short, control-character-free preview of the body."""
    text = _decode_body(body_bytes)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def normalized_body_hash(body_bytes):
    """Whitespace-insensitive hash used for soft-404 / baseline comparison."""
    if not body_bytes:
        return hashlib.sha256(b"").hexdigest()
    compact = re.sub(rb"\s+", b"", body_bytes)
    return hashlib.sha256(compact).hexdigest()


# ---------------------------------------------------------------------------
# Path heuristics
# ---------------------------------------------------------------------------

_BACKUP_PATH_RE = re.compile(
    r"(^|/)(backup|backups|bak|old|orig|\.old|\.bak|\.orig|\.swp|\.save|\.~|"
    r"~$|\.zip$|\.tar(\.gz)?$|\.tgz$|\.rar$|\.7z$|\.sql$|\.dump$|\.dmp$|\.gz$)",
    re.IGNORECASE,
)

_VCS_PATH_RE = re.compile(r"(^|/)(\.git|\.svn|\.hg|\.bzr|CVS)(/|$|\.)", re.IGNORECASE)

_ADMIN_PATH_RE = re.compile(
    r"(^|/)(admin|administrator|wp-admin|wp-login|phpmyadmin|pma|adminer|"
    r"dashboard|controlpanel|cpanel|whm|panel|console|jenkins|grafana|kibana|"
    r"manager|management|backoffice|superuser|useradmin|admin-console)(/|$|\.)",
    re.IGNORECASE,
)

_LOGIN_PATH_RE = re.compile(
    r"(^|/)(login|signin|sign-in|log-in|auth|authenticate|wp-login)(/|$|\.)",
    re.IGNORECASE,
)

_API_PATH_RE = re.compile(r"(^|/)(api|rest|graphql|swagger|v1|v2|v3|openapi)(/|$|\.)", re.IGNORECASE)

_CONFIG_PATH_RE = re.compile(
    r"(^|/)(wp-config|config|configuration|conf|cfg|settings|setup|install|env|"
    r"application\.|appsettings|web\.config|php\.ini|\.env|\.npmrc|\.pypirc|"
    r"\.gitconfig|\.htaccess|\.htpasswd|docker-compose|Dockerfile|"
    r"package\.json|package-lock|yarn\.lock|requirements\.txt|Pipfile|"
    r"composer\.json|Gemfile|pom\.xml|build\.gradle)(/|$|\.)",
    re.IGNORECASE,
)

_CREDENTIAL_PATH_RE = re.compile(
    r"(^|/)(credential|credentials|secret|secrets|token|tokens|passwd|"
    r"password|\.htpasswd|id_rsa|id_dsa|id_ed25519|\.pem|\.key|keystore|"
    r"auth\.json|service-account|api[-_]?key)(/|$|\.)",
    re.IGNORECASE,
)

_SOURCE_PATH_RE = re.compile(
    r"(^|/)(src|source|lib|vendor|node_modules|app|controllers|models|"
    r"services|routes|views|helpers|utils|\.py$|\.js$|\.ts$|\.java$|\.php$|"
    r"\.rb$|\.go$|\.c$|\.cpp$|\.cs$)(/|$|\.)",
    re.IGNORECASE,
)

_LOG_PATH_RE = re.compile(
    r"(^|/)(log|logs|debug|trace|access\.log|error\.log|\.log$|syslog|"
    r"auth\.log|audit\.log)(/|$|\.)",
    re.IGNORECASE,
)

_INTERNAL_PATH_RE = re.compile(
    r"(^|/)(internal|intranet|private|secret|hidden|backstage|internal-api|"
    r"corp|staff|employees?)(/|$|\.)",
    re.IGNORECASE,
)

# Paths that are *normal, expected* public resources.  Presence with a 2xx is
# NOT a finding by itself — these are only flagged if their *content* leaks
# something sensitive (e.g. robots.txt is public; robots.txt is not).
BENIGN_ASSET_PATTERNS = (
    r"^/robots\.txt$",
    r"^/sitemap.*\.xml$",
    r"^/favicon\.ico$",
    r"^/apple-touch-icon.*\.(png|ico)$",
    r"^/manifest\.json$",
    r"^/sw\.js$",
    r"^/service-worker\.js$",
    r"^/browserconfig\.xml$",
    r"^/site\.webmanifest$",
    r"^/\.well-known/",
    r"^/crossdomain\.xml$",
    r"^/clientaccesspolicy\.xml$",
    r"^/security\.txt$",
    r"^/humans\.txt$",
    r"^/license",  # license / license.txt / LICENSE
    r"^/changelog",
    r"^/readme",
    r"^/\.gitignore$",  # public by convention, but still inspect content
    r"^/\.dockerignore$",
    r"^/404\.html$",
    r"^/error\.html$",
    r"^/index\.html$",
    r"^/index\.php$",
    r"^/(css|js|img|images|image|icons|fonts|font|assets|static|media|"
    r"uploads?|files|public|dist|build|vendor|node_modules)/",
    r"\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|"
    r"pdf|webm|mp4|mp3)$",
    r"^/(about|contact|faq|help|terms|privacy|docs|documentation|blog|news|"
    r"download|downloads)(/|$)",
)

BENIGN_ASSET_RE = re.compile("|".join(BENIGN_ASSET_PATTERNS), re.IGNORECASE)

STATIC_ASSET_EXTENSIONS = re.compile(
    r"\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|"
    r"webm|mp4|mp3|txt)$", re.IGNORECASE,
)


def is_benign_asset(path):
    """True if the path is a normal, expected public web resource."""
    return bool(BENIGN_ASSET_RE.search(path))


def is_static_asset(path):
    return bool(STATIC_ASSET_EXTENSIONS.search(path))


# ---------------------------------------------------------------------------
# Content markers
# ---------------------------------------------------------------------------

# Directory listing (Apache index, nginx autoindex, IIS, lighttpd, generic)
DIRECTORY_LISTING_MARKERS = (
    "index of /",
    "index of/",
    "directory listing",
    "listing of ",
    "parent directory",
    "to parent directory",
    "<title>index of",
    "autoindex",
    "apache/2",
    "last modified",
    "name size description",
    "icons/folder.gif",
    "icons/back.gif",
)

# Environment files / key=value secrets
_ENV_KEY_RE = re.compile(
    r"(?im)^\s*[a-z_][a-z0-9_]*(?:_[a-z0-9_]+)*\s*=\s*\S+\s*$",
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret|password|passwd|pwd|token|client[_-]?secret|"
    r"access[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|"
    r"db[_-]?password|db[_-]?user|mysql[_-]?pass|redis[_-]?pass|aws[_-]?secret|"
    r"aws[_-]?access|session[_-]?secret|jwt[_-]?secret|oauth[_-]?secret|"
    r"slack[_-]?token|github[_-]?token|smtp[_-]?pass|mail[_-]?pass|"
    r"ssh[_-]?private|root[_-]?password|admin[_-]?password|"
    r"signing[_-]?key|encryption[_-]?key|stripe[_-]?key|twilio[_-]?auth)",
)

# Known credential / token formats (high confidence)
CREDENTIAL_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{36,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9\-_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|sk_live_[0-9a-zA-Z]{16,}"
    r"|sk_test_[0-9a-zA-Z]{16,}"
    r"|AIza[0-9A-Za-z\-_]{35}"
    r"|AKIA[0-9A-Z]{16}"
    r"|eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"|-----BEGIN PGP PRIVATE KEY BLOCK-----)",
)

_CREDENTIAL_ASSIGN_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"client[_-]?secret|private[_-]?key|token)\s*[:=]\s*[\"']?[^\s\"']{6,}",
)

# Database dumps
DB_DUMP_MARKERS = (
    "mysqldump",
    "mysql dump",
    "postgresql database dump",
    "pg_dump",
    "sqlite format 3",
    "dumping data for table",
    "table structure",
    "create table `",
    "insert into `",
    "insert into ",
    "drop table if exists",
    "-- phpmyadmin sql dump",
)

# Configuration files
CONFIG_MARKERS = (
    "<configuration>",
    "<appsettings>",
    "connectionstrings",
    "<web-app",
    "web.config",
    "php.ini",
    "listen 80",
    "listen 443",
    "server_name",
    "proxy_pass",
    "autoindex",
    "deny from all",
    "allow from all",
    "rewriteengine on",
    "upload_max_filesize",
)

# Log file markers
LOG_MARKERS = (
    "error_log",
    "access.log",
    "nginx-access",
    "apache-access",
    "httpd-access",
    "segfault",
    "stack trace",
    "traceback (most recent call last)",
    "php warning",
    "php fatal error",
    "exception in thread",
)
_ACCESS_LOG_LINE_RE = re.compile(
    r"^\S+ \S+ - - \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}", re.MULTILINE
)
_TIMESTAMP_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", re.MULTILINE
)
_LOG_LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|ERROR|FATAL)\b")

# Source code markers (only applied to non-HTML textual content)
SOURCE_CODE_MARKERS = (
    "<?php",
    "#include <",
    "import os",
    "import sys",
    "from flask",
    "from django",
    "module.exports",
    "export default",
    "require('",
    "require(\"",
    "package com.",
    "public class ",
    "def __init__",
    "app.get(",
    "app.post(",
    "router.get(",
    "router.post(",
    "@requestmapping",
    "using system;",
)
_SOURCE_CODE_LINE_RE = re.compile(
    r"(?m)^\s*(import|from|function|def|class|const|let|var|"
    r"module\.exports|require\(|@(get|post|put|delete|requestmapping)|"
    r"public\s+(class|static)|package\s+|using\s+\w+)\b",
)

# Internal paths / infrastructure leaks
INTERNAL_PATHS_MARKERS = (
    "c:\\users",
    "c:/users",
    "/home/",
    "/var/www",
    "/usr/local",
    "/etc/passwd",
    "/etc/shadow",
    "file:///",
    "localhost:",
    "127.0.0.1",
)
_PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b"
)

# Private / business-sensitive documents
PRIVATE_DOC_MARKERS = (
    "confidential",
    "internal use only",
    "do not distribute",
    "classified",
    "proprietary",
    "salary",
    "payroll",
    "ssn",
    "social security",
    "passport number",
    "credit card",
    "bank account",
    "nda",
    "non-disclosure",
)

# Debug / server metadata exposure
DEBUG_MARKERS = (
    "server status",
    "apache server status",
    "apache status",
    "scoreboard",
    "total accesses:",
    "cpu usage:",
    "debug_backtrace",
    "xdebug",
    "laravel debugbar",
    "whoops, looks like something went wrong",
    "exception details",
    "stack trace",
)

# Soft-404 / not-found markers (content that *looks* like a 404 page)
SOFT_404_MARKERS = (
    "404 not found",
    "not found",
    "page not found",
    "error 404",
    "the requested url was not found",
    "no such file or directory",
    "the resource you requested could not be found",
    "does not exist",
    "404 - page",
    "file not found",
    "no page found",
)

# Login / auth-wall content markers
LOGIN_FORM_RE = re.compile(
    r"<form[^>]*>.*?type=[\"']password[\"']",
    re.IGNORECASE | re.DOTALL,
)
LOGIN_TEXT_MARKERS = (
    "sign in",
    "sign-in",
    "log in",
    "login",
    "username",
    "user name",
    "password",
    "authentication required",
)

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect_sensitive_content(path, content_type, body_bytes, headers=None):
    """Inspect content and return a set of match labels (empty == no finding)."""
    headers = headers or {}
    mime, kind = normalize_content_type(content_type)
    matches = set()

    # Servers frequently serve text files (e.g. .env, .git/config) as
    # application/octet-stream. If the body decodes cleanly as UTF-8, treat it
    # as text so content markers are still inspected.
    if kind == "binary" and body_bytes:
        try:
            body_bytes.decode("utf-8")
            kind = "text"
        except UnicodeDecodeError:
            pass

    if kind in ("html", "xml", "json", "text"):
        text, _title = extract_text(body_bytes, kind)
        if text:
            # Directory listing
            if any(m in text for m in DIRECTORY_LISTING_MARKERS):
                matches.add("directory_listing")

            # Credentials / secrets / private keys
            # CREDENTIAL_RE (AKIA, ghp_, JWT, private keys, ...) is high
            # confidence and applies to every kind. The looser assignment
            # pattern (password=, token= ...) is restricted to non-HTML kinds:
            # HTML pages legitimately contain labels like "Password:" and
            # inline JS like "var token = ...", which would otherwise create
            # false positives on ordinary pages.
            if CREDENTIAL_RE.search(text):
                matches.add("credentials")
            if kind in ("text", "json", "xml") and _CREDENTIAL_ASSIGN_RE.search(text):
                matches.add("credentials")
            if "-----begin" in text and "private key" in text:
                matches.add("private_key")

            # Environment-style key=value blocks with sensitive keys.
            # Only inspected for plain text / JSON — HTML inline scripts would
            # otherwise cause false positives.
            if kind in ("text", "json"):
                env_candidates = _ENV_KEY_RE.findall(text)
                if env_candidates:
                    if any(_SENSITIVE_KEY_RE.search(line) for line in env_candidates[:200]):
                        matches.add("env_secrets")
                    elif len(env_candidates) >= 5:
                        matches.add("env_file")

            # Database dumps
            db_hits = sum(1 for m in DB_DUMP_MARKERS if m in text)
            if db_hits >= 2 or ("mysql dump" in text) or ("create table" in text and "insert into" in text):
                matches.add("db_dump")

            # Config files
            if kind == "xml" and ("<configuration>" in text or "<appsettings>" in text):
                matches.add("config_file")
            if any(m in text for m in CONFIG_MARKERS) and (
                kind in ("xml", "text") and ("=" in text or ":" in text)
            ):
                matches.add("config_file")

            # Log files
            if _ACCESS_LOG_LINE_RE.search(text):
                matches.add("log_file")
            if _TIMESTAMP_LINE_RE.search(text) and _LOG_LEVEL_RE.search(text):
                matches.add("log_file")
            if "error_log" in text or "stack trace" in text or "traceback" in text:
                matches.add("log_file")

            # Source code (only on textual, non-HTML content to avoid FP)
            if kind in ("text", "json") and (
                any(m in text for m in SOURCE_CODE_MARKERS)
                or _SOURCE_CODE_LINE_RE.search(text)
            ):
                matches.add("source_code")

            # Internal paths / IPs
            if any(m in text for m in INTERNAL_PATHS_MARKERS):
                matches.add("internal_paths")
            if _PRIVATE_IP_RE.search(text):
                matches.add("internal_paths")

            # Private documents
            if any(m in text for m in PRIVATE_DOC_MARKERS):
                matches.add("private_document")

            # Debug / server metadata
            if any(m in text for m in DEBUG_MARKERS):
                matches.add("debug_info")

        # JSON-specific deep scan for sensitive key names
        if kind == "json":
            try:
                parsed = json.loads(_decode_body(body_bytes))
                if _json_has_sensitive_data(parsed):
                    matches.add("sensitive_json")
            except (ValueError, TypeError):
                pass

    # Header-based signal: auth wall even with a 2xx status
    www_auth = (headers.get("www-authenticate") or "").lower()
    if www_auth:
        matches.add("auth_required")

    return matches


def _json_has_sensitive_data(obj, depth=0):
    """Recursively look for sensitive keys/values inside a JSON payload."""
    if depth > 4:
        return False
    sensitive_keys = {
        "password", "passwd", "pwd", "secret", "api_key", "apikey",
        "access_key", "accesskey", "token", "auth_token", "client_secret",
        "private_key", "aws_secret_access_key", "aws_access_key_id",
        "session_token", "refresh_token", "id_token", "authorization",
        "credit_card", "card_number", "cvv", "ssn", "social_security_number",
        "bank_account", "routing_number", "passport",
    }
    if isinstance(obj, dict):
        keys = set(obj.keys())
        if keys & sensitive_keys:
            return True
        return any(_json_has_sensitive_data(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return any(_json_has_sensitive_data(v, depth + 1) for v in obj[:100])
    if isinstance(obj, str):
        low = obj.lower()
        if CREDENTIAL_RE.search(obj):
            return True
        if any(k in low for k in ("password", "secret", "token=", "api_key=")):
            return True
    return False


def is_login_form_body(body_bytes, content_type):
    """Heuristic: 2xx page that is an authentication wall, not exposed content."""
    mime, kind = normalize_content_type(content_type)
    if kind != "html":
        return False
    text, title = extract_text(body_bytes, kind)
    has_password_field = bool(LOGIN_FORM_RE.search(text))
    if not has_password_field:
        return False
    hits = sum(1 for m in LOGIN_TEXT_MARKERS if m in text)
    return hits >= 2 or bool(re.search(r"\b(login|sign\s*in|log\s*in)\b", title or ""))


def is_soft_404_body(body_bytes, content_type, title=""):
    """Heuristic: 2xx response that actually represents a 404 page."""
    mime, kind = normalize_content_type(content_type)
    text, parsed_title = extract_text(body_bytes, kind)
    title = title or parsed_title
    if title and re.search(r"404|not found|does not exist", title, re.IGNORECASE):
        return True
    hits = sum(1 for m in SOFT_404_MARKERS if m in text)
    return hits >= 2


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify_category(path, content_type, matches, status, body_bytes=None):
    """Assign a category using content evidence first, then path heuristics."""
    p = path or ""
    p_lower = p.lower()

    # An environment file is an environment file by nature — this takes
    # precedence even when the content also matches credential patterns.
    if ".env" in p_lower:
        return CATEGORY_ENVIRONMENT_FILE

    # Content evidence has the highest weight
    if "directory_listing" in matches:
        return CATEGORY_DIRECTORY_LISTING
    if "db_dump" in matches:
        return CATEGORY_DATABASE_DUMP
    if "private_key" in matches or "credentials" in matches or "sensitive_json" in matches:
        return CATEGORY_CREDENTIALS
    if "env_secrets" in matches or "env_file" in matches:
        return CATEGORY_ENVIRONMENT_FILE
    if "config_file" in matches:
        return CATEGORY_CONFIG_FILE
    if "log_file" in matches:
        return CATEGORY_LOG_FILE
    if "source_code" in matches:
        return CATEGORY_SOURCE_CODE
    if "internal_paths" in matches:
        return CATEGORY_INTERNAL_PATH
    if "private_document" in matches:
        return CATEGORY_PRIVATE_DOCUMENT
    if "debug_info" in matches:
        return CATEGORY_SENSITIVE_METADATA

    # Path heuristics
    if _VCS_PATH_RE.search(p_lower):
        return CATEGORY_VCS_METADATA
    if _BACKUP_PATH_RE.search(p_lower):
        return CATEGORY_BACKUP_FILE
    if _CREDENTIAL_PATH_RE.search(p_lower):
        return CATEGORY_CREDENTIALS
    if _CONFIG_PATH_RE.search(p_lower):
        return CATEGORY_CONFIG_FILE
    if _LOG_PATH_RE.search(p_lower):
        return CATEGORY_LOG_FILE
    if _INTERNAL_PATH_RE.search(p_lower):
        return CATEGORY_INTERNAL_PATH
    if _SOURCE_PATH_RE.search(p_lower):
        return CATEGORY_SOURCE_CODE
    if _ADMIN_PATH_RE.search(p_lower):
        return CATEGORY_ADMIN_PANEL
    if _LOGIN_PATH_RE.search(p_lower):
        return CATEGORY_LOGIN_PAGE
    if _API_PATH_RE.search(p_lower):
        return CATEGORY_API_ENDPOINT
    if is_benign_asset(p):
        return CATEGORY_STATIC_ASSET if is_static_asset(p) else CATEGORY_PUBLIC_FILE

    if status == 404:
        return CATEGORY_NOT_FOUND
    if status and 300 <= status < 400:
        return CATEGORY_REDIRECT
    if status and status >= 500:
        return CATEGORY_ERROR
    return CATEGORY_PUBLIC_FILE


# ---------------------------------------------------------------------------
# Access status
# ---------------------------------------------------------------------------


def compute_access_status(
    status,
    matches,
    category,
    is_login_page,
    is_soft404=False,
    has_auth_header=False,
):
    """Map (status + content evidence) to a semantic access status."""
    if status in (0, None):
        return STATUS_UNREACHABLE
    if status == 404 or is_soft404:
        return STATUS_NOT_FOUND
    if has_auth_header or status in (401, 407):
        return STATUS_PROTECTED
    if status == 403:
        return STATUS_FORBIDDEN
    if status == 405:
        # Resource exists but the method is not allowed → not publicly readable
        return STATUS_RESTRICTED
    if status in (301, 302, 303, 307, 308):
        return STATUS_REDIRECTED
    if status >= 500:
        return STATUS_ERROR

    # 2xx responses — decide Exposed vs Public vs Restricted by content.
    # An authentication wall (login page) is Restricted by default; only
    # high-confidence evidence (actual tokens / keys / dumps) overrides it.
    if is_login_page:
        high_conf = bool(matches & {"private_key", "credentials", "db_dump", "env_secrets", "sensitive_json"})
        if high_conf:
            return STATUS_EXPOSED
        return STATUS_RESTRICTED
    exposed = bool(matches) or category in EXPOSED_BY_NATURE
    if category == CATEGORY_ADMIN_PANEL:
        exposed = True
    if exposed:
        return STATUS_EXPOSED
    return STATUS_PUBLIC


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

# Base risk weight per category (business impact of exposure)
_CATEGORY_RISK_WEIGHT = {
    CATEGORY_CREDENTIALS: 10,
    CATEGORY_DATABASE_DUMP: 10,
    CATEGORY_ENVIRONMENT_FILE: 9,
    CATEGORY_BACKUP_FILE: 9,
    CATEGORY_VCS_METADATA: 8,
    CATEGORY_CONFIG_FILE: 7,
    CATEGORY_SOURCE_CODE: 7,
    CATEGORY_LOG_FILE: 6,
    CATEGORY_PRIVATE_DOCUMENT: 6,
    CATEGORY_INTERNAL_PATH: 6,
    CATEGORY_SENSITIVE_METADATA: 5,
    CATEGORY_DIRECTORY_LISTING: 4,
    CATEGORY_ADMIN_PANEL: 5,
    CATEGORY_API_ENDPOINT: 3,
    CATEGORY_LOGIN_PAGE: 1,
    CATEGORY_PUBLIC_FILE: 0,
    CATEGORY_STATIC_ASSET: 0,
}

_MATCH_BONUS = {
    "private_key": 3,
    "credentials": 2,
    "sensitive_json": 2,
    "env_secrets": 3,
    "db_dump": 2,
    "config_file": 1,
    "internal_paths": 1,
    "debug_info": 1,
    "log_file": 1,
}


def compute_risk(status, category, access_status, matches, is_login_page):
    """Multi-factor risk: content sensitivity, auth, misconfig, disclosure,
    exploitability and business impact."""
    # Unreachable / server-side errors / not found carry no exploitable risk
    if status in (0, None):
        return "LOW"
    if access_status in (STATUS_NOT_FOUND, STATUS_FORBIDDEN, STATUS_PROTECTED, STATUS_ERROR, STATUS_REDIRECTED):
        return "LOW"
    if access_status == STATUS_UNREACHABLE:
        return "LOW"

    # Behind an auth wall: only an exposed admin/login surface is meaningful
    if access_status == STATUS_RESTRICTED:
        return "MEDIUM" if category == CATEGORY_ADMIN_PANEL else "LOW"

    # Exposed or Public — score from content sensitivity + evidence
    score = _CATEGORY_RISK_WEIGHT.get(category, 0)
    for m in matches:
        score += _MATCH_BONUS.get(m, 0)

    # Exploitability adders
    if category == CATEGORY_ADMIN_PANEL and not is_login_page:
        score += 3  # admin panel served without an auth wall
    if category == CATEGORY_DIRECTORY_LISTING:
        score += 0  # already weighted; misconfiguration factor is the category

    if score >= 12:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def analyze_response(url, status, headers, body_bytes, baseline_hash=None, content_length=None):
    """
    Full content-based analysis of a probed resource.

    Returns a dict with: found, status, content_type, content_length, category,
    risk, access_status, is_sensitive, sensitive_matches, title, preview,
    is_soft404.
    """
    content_type = (headers or {}).get("content-type", "")
    if content_length is None:
        content_length = len(body_bytes) if body_bytes else 0

    # Soft-404: identical (normalized) body to the site baseline.
    # Only applies to 2xx responses — an identical 401/403 body across paths is
    # a genuine access-denied response (e.g. a WAF), not a catch-all page.
    is_soft404 = False
    if baseline_hash and status in (200, 201, 204):
        is_soft404 = normalized_body_hash(body_bytes) == baseline_hash

    matches = detect_sensitive_content(url, content_type, body_bytes, headers)
    mime, kind = normalize_content_type(content_type)
    _text, title = extract_text(body_bytes, kind)

    if not is_soft404 and status == 200:
        is_soft404 = is_soft_404_body(body_bytes, content_type, title)

    is_login_page = (
        status == 200
        and not is_soft404
        and is_login_form_body(body_bytes, content_type)
    )

    category = classify_category(url, content_type, matches, status, body_bytes)
    has_auth_header = bool((headers or {}).get("www-authenticate"))
    access_status = compute_access_status(
        status, matches, category, is_login_page,
        is_soft404=is_soft404, has_auth_header=has_auth_header,
    )
    risk = compute_risk(status, category, access_status, matches, is_login_page)

    # A resource is "sensitive" if it is (or could be) an information disclosure
    is_sensitive = (
        category in SENSITIVE_CATEGORIES
        or bool(matches)
        or access_status == STATUS_EXPOSED
    )

    return {
        "found": status != 404 and not is_soft404,
        "status": status,
        "content_type": content_type,
        "content_length": content_length,
        "category": category,
        "risk": risk,
        "access_status": access_status,
        "is_sensitive": is_sensitive,
        "sensitive_matches": sorted(matches),
        "title": title,
        "preview": sanitize_preview(body_bytes) if body_bytes else "",
        "is_soft404": is_soft404,
    }


def analyze_entry(url, status, content_type="", content_length=0):
    """
    Classify an entry WITHOUT a response body (e.g. results parsed from the
    dirsearch binary JSON output). Uses path + status heuristics only.
    """
    matches = set()
    p = (url or "").lower()
    if _VCS_PATH_RE.search(p) or ".git" in p:
        matches.add("vcs_metadata")
    if _BACKUP_PATH_RE.search(p):
        matches.add("backup_file")
    if _CREDENTIAL_PATH_RE.search(p):
        matches.add("credentials")
    if ".env" in p:
        matches.add("env_secrets")

    category = classify_category(url, content_type, matches, status)
    has_auth_header = False
    access_status = compute_access_status(
        status, matches, category, is_login_page=False,
        is_soft404=False, has_auth_header=has_auth_header,
    )
    # Without a body we cannot confirm a login wall
    if status in (200, 201, 204) and category == CATEGORY_LOGIN_PAGE:
        access_status = STATUS_RESTRICTED
    risk = compute_risk(status, category, access_status, matches, is_login_page=False)
    is_sensitive = category in SENSITIVE_CATEGORIES or bool(matches)

    return {
        "found": status != 404,
        "status": status,
        "content_type": content_type,
        "content_length": content_length,
        "category": category,
        "risk": risk,
        "access_status": access_status,
        "is_sensitive": is_sensitive,
        "sensitive_matches": sorted(matches),
        "title": "",
        "preview": "",
        "is_soft404": False,
    }
