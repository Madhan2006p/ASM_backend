"""
Unit tests for the content-based directory analysis engine.

These tests lock in the core behavior requested by the module audit:

* A 200 response is NOT automatically "Exposed".
* Normal public resources (robots.txt, sitemap.xml, favicon, static assets,
  generic public API responses, login pages) are classified as Public /
  Restricted with LOW risk.
* Sensitive content (credentials, db dumps, directory listings, backups,
  env files, VCS metadata, debug info) is flagged Exposed with appropriate risk.
* Soft-404 pages (2xx with the same body as the site baseline) are rejected.
* Status mappings (Public / Protected / Restricted / Exposed / Not Found /
  Forbidden / Redirected / Error) are validated.
"""

from django.test import SimpleTestCase

from .scanner.directory_analyzer import (
    CATEGORY_ADMIN_PANEL,
    CATEGORY_API_ENDPOINT,
    CATEGORY_BACKUP_FILE,
    CATEGORY_CREDENTIALS,
    CATEGORY_DIRECTORY_LISTING,
    CATEGORY_ENVIRONMENT_FILE,
    CATEGORY_LOGIN_PAGE,
    CATEGORY_PUBLIC_FILE,
    CATEGORY_SENSITIVE_METADATA,
    CATEGORY_SOURCE_CODE,
    CATEGORY_STATIC_ASSET,
    CATEGORY_VCS_METADATA,
    STATUS_ERROR,
    STATUS_EXPOSED,
    STATUS_FORBIDDEN,
    STATUS_NOT_FOUND,
    STATUS_PROTECTED,
    STATUS_PUBLIC,
    STATUS_REDIRECTED,
    STATUS_RESTRICTED,
    STATUS_UNREACHABLE,
    analyze_entry,
    analyze_response,
    normalized_body_hash,
)

HTML = "text/html"
PLAIN = "text/plain"
JSON = "application/json"


class AnalyzeResponseTests(SimpleTestCase):
    """Full content-based analysis (status + headers + body)."""

    def test_robots_txt_is_public_not_exposed(self):
        result = analyze_response(
            "https://example.com/robots.txt",
            200,
            {"content-type": PLAIN},
            b"User-agent: *\nDisallow: /admin\n",
        )
        self.assertEqual(result["access_status"], STATUS_PUBLIC)
        self.assertEqual(result["category"], CATEGORY_PUBLIC_FILE)
        self.assertEqual(result["risk"], "LOW")
        self.assertFalse(result["is_sensitive"])
        self.assertFalse(result["sensitive_matches"])

    def test_sitemap_xml_is_public(self):
        result = analyze_response(
            "https://example.com/sitemap.xml",
            200,
            {"content-type": "application/xml"},
            b"<?xml version=\"1.0\"?><urlset><url><loc>https://example.com/</loc></url></urlset>",
        )
        self.assertEqual(result["access_status"], STATUS_PUBLIC)
        self.assertEqual(result["risk"], "LOW")

    def test_favicon_is_static_asset(self):
        result = analyze_response(
            "https://example.com/favicon.ico",
            200,
            {"content-type": "image/x-icon"},
            b"\x00\x00\x01\x00binary",
        )
        self.assertEqual(result["category"], CATEGORY_STATIC_ASSET)
        self.assertEqual(result["access_status"], STATUS_PUBLIC)
        self.assertEqual(result["risk"], "LOW")

    def test_generic_public_api_is_low_risk(self):
        result = analyze_response(
            "https://example.com/api/v1/status",
            200,
            {"content-type": JSON},
            b'{"status": "ok", "uptime": 12345}',
        )
        self.assertEqual(result["category"], CATEGORY_API_ENDPOINT)
        self.assertEqual(result["access_status"], STATUS_PUBLIC)
        self.assertEqual(result["risk"], "LOW")
        self.assertFalse(result["is_sensitive"])

    def test_login_page_is_restricted_not_exposed(self):
        result = analyze_response(
            "https://example.com/login",
            200,
            {"content-type": HTML},
            b"<html><head><title>Sign In</title></head><body>"
            b"<form action=\"/login\" method=\"post\">"
            b"<input name=\"username\" type=\"text\">"
            b"<input name=\"password\" type=\"password\">"
            b"<button>Login</button></form></body></html>",
        )
        self.assertEqual(result["category"], CATEGORY_LOGIN_PAGE)
        self.assertEqual(result["access_status"], STATUS_RESTRICTED)
        self.assertEqual(result["risk"], "LOW")
        self.assertFalse(result["is_sensitive"])

    def test_env_file_with_secrets_is_exposed_critical(self):
        body = b"DB_PASSWORD=SuperSecret123\nAPI_KEY=abcd1234\nSECRET_TOKEN=xyz\n"
        result = analyze_response(
            "https://example.com/.env",
            200,
            {"content-type": PLAIN},
            body,
        )
        self.assertEqual(result["category"], CATEGORY_ENVIRONMENT_FILE)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "CRITICAL")
        self.assertTrue(result["is_sensitive"])
        self.assertIn("env_secrets", result["sensitive_matches"])

    def test_login_page_with_password_label_is_restricted_not_exposed(self):
        # A login page that shows a visible "Password:" label must NOT be
        # flagged as an exposed credential leak.
        body = (
            b"<html><head><title>Sign In</title></head><body>"
            b"<form action=\"/login\" method=\"post\">"
            b"<label for=\"user\">Username:</label>"
            b"<input id=\"user\" name=\"username\" type=\"text\">"
            b"<label for=\"pass\">Password:</label>"
            b"<input id=\"pass\" name=\"password\" type=\"password\">"
            b"<button type=\"submit\">Login</button></form></body></html>"
        )
        result = analyze_response(
            "https://example.com/login",
            200,
            {"content-type": HTML},
            body,
        )
        self.assertEqual(result["access_status"], STATUS_RESTRICTED)
        self.assertEqual(result["risk"], "LOW")
        self.assertFalse(result["is_sensitive"])

    def test_env_file_served_as_octet_stream_is_still_detected(self):
        # Many servers (e.g. Python's http.server) serve .env as
        # application/octet-stream — content inspection must still apply.
        body = b"DB_PASSWORD=SuperSecret123\nAPI_KEY=abcd1234\nSECRET_TOKEN=xyz\n"
        result = analyze_response(
            "https://example.com/.env",
            200,
            {"content-type": "application/octet-stream"},
            body,
        )
        self.assertEqual(result["category"], CATEGORY_ENVIRONMENT_FILE)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "CRITICAL")
        self.assertTrue(result["is_sensitive"])

    def test_credentials_in_json_are_exposed_critical(self):
        body = b'{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "user": "admin"}'
        result = analyze_response(
            "https://example.com/api/token",
            200,
            {"content-type": JSON},
            body,
        )
        self.assertEqual(result["category"], CATEGORY_CREDENTIALS)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "CRITICAL")

    def test_directory_listing_is_exposed_medium(self):
        body = (
            b"<html><head><title>Index of /backup</title></head><body>"
            b"<pre><a href=\"../\">Parent Directory</a> 2024-01-01 10:00 "
            b"<a href=\"db.sql\">db.sql</a></pre></body></html>"
        )
        result = analyze_response(
            "https://example.com/backup/",
            200,
            {"content-type": HTML},
            body,
        )
        self.assertEqual(result["category"], CATEGORY_DIRECTORY_LISTING)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "MEDIUM")

    def test_backup_archive_is_exposed_high(self):
        result = analyze_response(
            "https://example.com/backup.zip",
            200,
            {"content-type": "application/zip"},
            b"PK\x03\x04binary-archive-data",
        )
        self.assertEqual(result["category"], CATEGORY_BACKUP_FILE)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "HIGH")

    def test_wp_config_php_is_config_file(self):
        result = analyze_response(
            "https://example.com/wp-config.php",
            403,
            {"content-type": HTML},
            b"<html><body>Forbidden</body></html>",
        )
        self.assertEqual(result["category"], "Config File")
        self.assertEqual(result["access_status"], STATUS_FORBIDDEN)
        self.assertEqual(result["risk"], "LOW")

    def test_git_config_is_exposed_high(self):
        result = analyze_response(
            "https://example.com/.git/config",
            200,
            {"content-type": PLAIN},
            b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:acme/app.git\n",
        )
        self.assertEqual(result["category"], CATEGORY_VCS_METADATA)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "HIGH")

    def test_server_status_is_sensitive_metadata(self):
        body = (
            b"<html><head><title>Apache Status</title></head><body>"
            b"Apache Server Status for example.com - Scoreboard: ____R____W... "
            b"Total accesses: 12345 - Total Traffic: 6.7 MB</body></html>"
        )
        result = analyze_response(
            "https://example.com/server-status",
            200,
            {"content-type": HTML},
            body,
        )
        self.assertEqual(result["category"], CATEGORY_SENSITIVE_METADATA)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "MEDIUM")

    def test_forbidden_is_low_risk(self):
        result = analyze_response(
            "https://example.com/admin",
            403,
            {"content-type": HTML},
            b"<html><body>Forbidden</body></html>",
        )
        self.assertEqual(result["access_status"], STATUS_FORBIDDEN)
        self.assertEqual(result["risk"], "LOW")
        self.assertTrue(result["found"])

    def test_unauthorized_is_protected(self):
        result = analyze_response(
            "https://example.com/api/v1/users",
            401,
            {"content-type": JSON},
            b'{"error": "unauthorized"}',
        )
        self.assertEqual(result["access_status"], STATUS_PROTECTED)
        self.assertEqual(result["risk"], "LOW")

    def test_redirect_is_redirected(self):
        result = analyze_response(
            "https://example.com/dashboard",
            302,
            {"content-type": HTML, "location": "/login"},
            b"",
        )
        self.assertEqual(result["access_status"], STATUS_REDIRECTED)
        self.assertEqual(result["risk"], "LOW")

    def test_server_error_is_error(self):
        result = analyze_response(
            "https://example.com/admin",
            500,
            {"content-type": HTML},
            b"<html><body>Internal Server Error</body></html>",
        )
        self.assertEqual(result["access_status"], STATUS_ERROR)
        self.assertEqual(result["risk"], "LOW")

    def test_soft404_identical_to_baseline_is_not_found(self):
        baseline = b"<html><head><title>Home</title></head><body>Welcome</body></html>"
        baseline_hash = normalized_body_hash(baseline)
        result = analyze_response(
            "https://example.com/nonexistent-path",
            200,
            {"content-type": HTML},
            baseline,
            baseline_hash=baseline_hash,
        )
        self.assertTrue(result["is_soft404"])
        self.assertFalse(result["found"])
        self.assertEqual(result["access_status"], STATUS_NOT_FOUND)
        self.assertEqual(result["risk"], "LOW")

    def test_404_page_body_is_not_found(self):
        result = analyze_response(
            "https://example.com/whatever",
            200,
            {"content-type": HTML},
            b"<html><head><title>404 - Page not found</title></head>"
            b"<body><h1>Not Found</h1><p>The requested URL was not found.</p></body></html>",
        )
        self.assertEqual(result["access_status"], STATUS_NOT_FOUND)
        self.assertEqual(result["risk"], "LOW")

    def test_unreachable(self):
        result = analyze_response(
            "https://example.com/anything",
            0,
            {},
            b"",
        )
        self.assertEqual(result["access_status"], STATUS_UNREACHABLE)
        self.assertEqual(result["risk"], "LOW")

    def test_admin_panel_without_auth_wall_is_exposed(self):
        # Admin panel 200 that is NOT a login form → publicly reachable admin
        result = analyze_response(
            "https://example.com/admin/",
            200,
            {"content-type": HTML},
            b"<html><head><title>Admin Dashboard</title></head><body>"
            b"<h1>Site administration</h1><table><tr><td>Users</td></tr></table></body></html>",
        )
        self.assertEqual(result["category"], CATEGORY_ADMIN_PANEL)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "HIGH")

    def test_source_code_exposed(self):
        result = analyze_response(
            "https://example.com/app.py",
            200,
            {"content-type": PLAIN},
            b"import os\nfrom flask import Flask\napp = Flask(__name__)\ndef index():\n    return 'hi'\n",
        )
        self.assertEqual(result["category"], CATEGORY_SOURCE_CODE)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)

    def test_plain_homepage_is_public(self):
        result = analyze_response(
            "https://example.com/",
            200,
            {"content-type": HTML},
            b"<html><head><title>Welcome to Example</title></head>"
            b"<body><p>We build software.</p></body></html>",
        )
        self.assertEqual(result["access_status"], STATUS_PUBLIC)
        self.assertEqual(result["risk"], "LOW")
        self.assertFalse(result["is_sensitive"])

    def test_identical_401_body_to_baseline_is_not_soft404(self):
        # A WAF/401 wall returning the same body for every path is a genuine
        # access-denied response, NOT a catch-all 200 page.
        body = b"<html><body>Access Denied</body></html>"
        baseline_hash = normalized_body_hash(body)
        result = analyze_response(
            "https://example.com/anything",
            401,
            {"content-type": HTML},
            body,
            baseline_hash=baseline_hash,
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["access_status"], STATUS_PROTECTED)
        self.assertEqual(result["risk"], "LOW")

    def test_identical_403_body_to_baseline_is_not_soft404(self):
        body = b"<html><body>Forbidden</body></html>"
        baseline_hash = normalized_body_hash(body)
        result = analyze_response(
            "https://example.com/assets/",
            403,
            {"content-type": HTML},
            body,
            baseline_hash=baseline_hash,
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["access_status"], STATUS_FORBIDDEN)
        self.assertEqual(result["risk"], "LOW")


class FetchRedirectTests(SimpleTestCase):
    """Scanner redirect handling: record the FINAL status a browser sees."""

    class FakeResp:
        def __init__(self, status, headers, chunks=()):
            self.status_code = status
            self.headers = headers
            self._chunks = chunks

        def iter_bytes(self):
            yield from self._chunks

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class FakeClient:
        def __init__(self, responses):
            self.responses = responses
            self.calls = []

        def stream(self, method, url, **kwargs):
            self.calls.append(url)
            return self.responses[url]

    def test_fetch_follows_relative_redirect_to_final_status(self):
        from .scanner.directory_scanner import _fetch

        client = self.FakeClient({
            "https://example.com/assets": self.FakeResp(301, {"location": "/assets/"}),
            "https://example.com/assets/": self.FakeResp(403, {"content-type": "text/html"}, [b"<html>Forbidden</html>"]),
        })
        status, headers, body = _fetch(client, "https://example.com/assets")
        self.assertEqual(status, 403)
        self.assertIn(b"Forbidden", body)
        self.assertEqual(
            client.calls,
            ["https://example.com/assets", "https://example.com/assets/"],
        )

    def test_fetch_follows_absolute_redirect_chain(self):
        from .scanner.directory_scanner import _fetch

        client = self.FakeClient({
            "https://example.com/dashboard": self.FakeResp(302, {"location": "https://auth.example.com/login"}),
            "https://auth.example.com/login": self.FakeResp(200, {"content-type": "text/html"}, [b"<html>Sign in</html>"]),
        })
        status, _headers, body = _fetch(client, "https://example.com/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Sign in", body)

    def test_fetch_caps_redirect_hops(self):
        from .scanner.directory_scanner import _fetch

        client = self.FakeClient({
            f"https://example.com/hop{i}": self.FakeResp(302, {"location": f"/hop{i + 1}"})
            for i in range(10)
        })
        client.responses["https://example.com/hop0"] = self.FakeResp(302, {"location": "/hop1"})
        status, _headers, _body = _fetch(client, "https://example.com/hop0")
        self.assertIsNone(status)  # loop/hop-exhaustion → treated as unreachable

    def test_baseline_fetch_follows_redirects(self):
        from .scanner.directory_scanner import _fetch_baseline, normalized_body_hash

        client = self.FakeClient({
            "http://example.com": self.FakeResp(301, {"location": "https://example.com/"}),
            "https://example.com/": self.FakeResp(200, {"content-type": "text/html"}, [b"<html>Home</html>"]),
        })
        baseline = _fetch_baseline(client, "http://example.com")
        self.assertEqual(baseline, normalized_body_hash(b"<html>Home</html>"))


class AnalyzeEntryTests(SimpleTestCase):
    """Body-less classification (dirsearch binary output / legacy rows)."""

    def test_admin_entry(self):
        result = analyze_entry("https://example.com/admin", 200, HTML)
        self.assertEqual(result["category"], CATEGORY_ADMIN_PANEL)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)

    def test_env_entry(self):
        result = analyze_entry("https://example.com/.env", 200, PLAIN)
        self.assertEqual(result["category"], CATEGORY_ENVIRONMENT_FILE)
        self.assertEqual(result["access_status"], STATUS_EXPOSED)
        self.assertEqual(result["risk"], "CRITICAL")

    def test_backup_entry_forbidden(self):
        result = analyze_entry("https://example.com/backup.zip", 403, HTML)
        self.assertEqual(result["category"], CATEGORY_BACKUP_FILE)
        self.assertEqual(result["access_status"], STATUS_FORBIDDEN)
        self.assertEqual(result["risk"], "LOW")

    def test_login_entry(self):
        result = analyze_entry("https://example.com/login", 200, HTML)
        self.assertEqual(result["category"], CATEGORY_LOGIN_PAGE)
        self.assertEqual(result["access_status"], STATUS_RESTRICTED)
        self.assertEqual(result["risk"], "LOW")

    def test_robots_entry(self):
        result = analyze_entry("https://example.com/robots.txt", 200, PLAIN)
        self.assertEqual(result["access_status"], STATUS_PUBLIC)
        self.assertEqual(result["risk"], "LOW")
