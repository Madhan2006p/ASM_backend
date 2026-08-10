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


class RedirectToHttpsTests(SimpleTestCase):
    """Plaintext-HTTP false-positive guard: 3xx to https:// is not an exposure."""

    class FakeResp:
        def __init__(self, status, headers):
            self.status_code = status
            self.headers = headers

    def _run(self, url, status, headers):
        from unittest import mock
        from .scanner.vulnerability_scanner import redirects_to_https

        with mock.patch("httpx.get", return_value=self.FakeResp(status, headers)):
            return redirects_to_https(url)

    def test_301_to_https_is_suppressed(self):
        self.assertTrue(
            self._run("http://uit.ac.in", 301, {"location": "https://uit.ac.in/"})
        )

    def test_302_to_https_is_suppressed(self):
        self.assertTrue(
            self._run("http://example.com", 302, {"location": "https://example.com/"})
        )

    def test_200_over_http_is_reported(self):
        self.assertFalse(self._run("http://example.com", 200, {"content-type": "text/html"}))

    def test_redirect_to_http_is_reported(self):
        # http:// -> http:// is NOT an upgrade; plaintext exposure remains.
        self.assertFalse(
            self._run("http://example.com", 301, {"location": "http://example.com/www"})
        )

    def test_flapping_node_redirecting_on_retry_is_suppressed(self):
        """
        Re-verification guard: one probe hits a node serving plaintext (200),
        a later probe proves the 301 -> https:// upgrade. The endpoint must be
        treated as redirecting (no plaintext false positive).
        """
        from unittest import mock
        from .scanner.vulnerability_scanner import redirects_to_https

        class PlainResp:
            status_code = 200
            headers = {"content-type": "text/html"}

        class RedirectResp:
            status_code = 301
            headers = {"location": "https://example.com/"}

        def flaky_get(*args, **kwargs):
            flaky_get.calls += 1
            return PlainResp() if flaky_get.calls == 1 else RedirectResp()
        flaky_get.calls = 0

        with mock.patch("httpx.get", side_effect=flaky_get):
            self.assertTrue(redirects_to_https("http://example.com"))
        self.assertGreaterEqual(flaky_get.calls, 2)

    def test_protocol_relative_location_is_reported(self):
        # "//host/" over HTTP resolves to the same scheme (http), not https.
        self.assertFalse(
            self._run("http://example.com", 301, {"location": "//example.com/"})
        )

    def test_non_http_url_returns_false(self):
        self.assertFalse(self._run("https://example.com", 301, {"location": "https://example.com/"}))


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


class _FakeNvdResp:
    """Minimal fake for the NVD API response (status_code + .json())."""
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class CVEEnrichmentTests(SimpleTestCase):
    """NVD CVE enrichment: tech/version parsing + NVD response parsing."""

    def _nvd_payload(self, cve_id, score, sev, desc):
        return {"vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": desc}],
                "metrics": {"cvssMetricV31": [{
                    "cvssData": {"baseScore": score, "baseSeverity": sev}
                }]},
                "references": [{"url": f"https://example.com/ref/{cve_id}"}],
            }
        }]}

    # ── parse_tech_entry ──
    def test_parse_httpx_slash_version(self):
        from .cve_enrichment import parse_tech_entry
        name, version = parse_tech_entry("nginx/1.18.0 [HTTPX]")
        self.assertEqual(name, "nginx")
        self.assertEqual(version, "1.18.0")

    def test_parse_whatcms_trailing_version(self):
        from .cve_enrichment import parse_tech_entry
        name, version = parse_tech_entry("Apache HTTP Server 2.4.10 [WhatCMS]")
        self.assertEqual(name, "apache http server")
        self.assertEqual(version, "2.4.10")

    def test_parse_tech_without_version(self):
        from .cve_enrichment import parse_tech_entry
        name, version = parse_tech_entry("WordPress [Wappalyzer]")
        self.assertEqual(name, "wordpress")
        self.assertEqual(version, "")

    def test_parse_cloudflare_skipped(self):
        from .cve_enrichment import parse_tech_entry
        name, _ = parse_tech_entry("Cloudflare [Header Analysis]")
        self.assertEqual(name, "cloudflare")

    # ── lookup_cves (mocked NVD) ──
    def test_lookup_cves_maps_score_severity_and_references(self):
        from unittest import mock
        from .cve_enrichment import lookup_cves

        payload = self._nvd_payload("CVE-2021-41773", 7.5, "HIGH", "Path traversal in Apache 2.4.49")
        with mock.patch(
            "attacksurface.cve_enrichment.httpx.get"
        ) as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = payload
            cves = lookup_cves("apache http server", "2.4.49")

        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(cves[0]["cvss_score"], 7.5)
        self.assertEqual(cves[0]["severity"], "HIGH")
        self.assertIn("https://example.com/ref/CVE-2021-41773", cves[0]["references"])
        self.assertEqual(cves[0]["nvd_url"], "https://nvd.nist.gov/vuln/detail/CVE-2021-41773")

    def test_lookup_cves_fails_open_on_http_error(self):
        from unittest import mock
        from .cve_enrichment import lookup_cves

        with mock.patch(
            "attacksurface.cve_enrichment.httpx.get"
        ) as mock_get:
            mock_get.return_value.status_code = 429
            cves = lookup_cves("nginx", "1.18.0")
        self.assertEqual(cves, [])

    def test_lookup_cves_fails_open_on_exception(self):
        from unittest import mock
        from .cve_enrichment import lookup_cves

        with mock.patch(
            "attacksurface.cve_enrichment.httpx.get",
            side_effect=Exception("network down"),
        ):
            cves = lookup_cves("nginx", "1.18.0")
        self.assertEqual(cves, [])

    def test_lookup_cves_skips_missing_version(self):
        from .cve_enrichment import lookup_cves
        self.assertEqual(lookup_cves("wordpress", ""), [])

    # ── CPE affected-range matching ──
    def test_cpe_exact_version_match(self):
        from .cve_enrichment import _cpe_match_applies
        self.assertTrue(_cpe_match_applies(
            "1.18.0", {"criteria": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"}
        ))
        self.assertFalse(_cpe_match_applies(
            "1.20.1", {"criteria": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"}
        ))

    def test_cpe_range_end_excluding(self):
        from .cve_enrichment import _cpe_match_applies
        match = {
            "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "1.20.1",
        }
        self.assertTrue(_cpe_match_applies("1.18.0", match))
        self.assertFalse(_cpe_match_applies("1.21.0", match))

    def test_cpe_range_start_including(self):
        from .cve_enrichment import _cpe_match_applies
        match = {
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.49",
            "versionEndIncluding": "2.4.50",
        }
        self.assertTrue(_cpe_match_applies("2.4.49", match))
        self.assertTrue(_cpe_match_applies("2.4.50", match))
        self.assertFalse(_cpe_match_applies("2.4.48", match))

    def test_open_wildcard_without_bounds_is_not_matched_strict(self):
        from .cve_enrichment import _cpe_match_applies
        self.assertFalse(_cpe_match_applies(
            "1.18.0", {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}
        ))

    def test_open_wildcard_matched_when_accepted(self):
        from .cve_enrichment import _cpe_match_applies
        self.assertTrue(_cpe_match_applies(
            "1.18.0",
            {"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
            accept_open_wildcard=True,
        ))

    def test_lookup_cves_fallback_uses_cpe_match(self):
        from unittest import mock
        from .cve_enrichment import lookup_cves

        keyword_payload = {"vulnerabilities": []}
        fallback_payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2021-23017",
            "descriptions": [{"lang": "en", "value": "A security issue in nginx resolver."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"}}]},
            "references": [{"url": "https://example.com/ref/CVE-2021-23017"}],
            "configurations": {"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "1.20.1",
            }]}]},
        }}]}
        with mock.patch(
            "attacksurface.cve_enrichment.httpx.get"
        ) as mock_get:
            mock_get.side_effect = [
                _FakeNvdResp(200, keyword_payload),
                _FakeNvdResp(200, fallback_payload),
            ]
            cves = lookup_cves("nginx", "1.18.0")

        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["cve_id"], "CVE-2021-23017")
        self.assertEqual(cves[0]["cvss_score"], 7.7)


class SSLProtocolAttackTests(SimpleTestCase):
    """Named TLS attack findings (BEAST / POODLE / Lucky13 / RC4 / 3DES)."""

    def test_add_protocol_attack_appends_finding_and_penalty(self):
        from attacksurface.scanner.ssl_scanner import _add_protocol_attack

        results = {"vulnerabilities": [], "attack_grade_penalty": 0}
        _add_protocol_attack(results, "example.com", 443, "BEAST", "TLS 1.0 enabled")

        self.assertEqual(len(results["vulnerabilities"]), 1)
        v = results["vulnerabilities"][0]
        self.assertEqual(v["vulnerability_id"], "SSL-BEAST")
        self.assertEqual(v["cve"], "CVE-2011-3389")
        self.assertEqual(v["severity"], "MEDIUM")
        self.assertEqual(results["attack_grade_penalty"], 15)

        # Dedup: adding the same attack twice must not duplicate
        _add_protocol_attack(results, "example.com", 443, "BEAST", "TLS 1.0 enabled")
        self.assertEqual(len(results["vulnerabilities"]), 1)
        self.assertEqual(results["attack_grade_penalty"], 15)

    def test_pooodle_and_lucky13_detection_happy_path(self):
        from unittest import mock
        from attacksurface.scanner.ssl_scanner import audit_ssl_cipher_suites

        def fake_ssl3(host, port=443, timeout=5):
            return True  # server accepts SSL 3.0 -> POODLE

        with mock.patch(
            "attacksurface.scanner.ssl_scanner._check_ssl3_supported",
            side_effect=fake_ssl3,
        ), mock.patch(
            "attacksurface.scanner.ssl_scanner._check_heartbleed",
            return_value=False,
        ), mock.patch(
            "attacksurface.scanner.ssl_scanner._extract_cert_info",
            return_value={"notBefore": "01-01-2025", "notAfter": "01-01-2027", "issuer": "Test CA", "is_trusted": True},
        ), mock.patch(
            "attacksurface.scanner.ssl_scanner.socket.create_connection",
            side_effect=Exception("no network in tests"),
        ):
            results = audit_ssl_cipher_suites("example.com", timeout=1)

        ids = {v["vulnerability_id"] for v in results["vulnerabilities"]}
        # Without network, no protocols/ciphers are observed -> only POODLE from the SSLv3 probe
        self.assertIn("SSL-POODLE", ids)
        # POODLE (HIGH) carries a 25-point grade penalty: 100 - 25 = 75 -> "C"
        self.assertEqual(results["ssl_grade"], "C")

    def test_lucky13_detected_for_cbc_cipher(self):
        from attacksurface.scanner.ssl_scanner import _add_protocol_attack

        results = {"vulnerabilities": [], "attack_grade_penalty": 0}
        _add_protocol_attack(results, "example.com", 443, "LUCKY13", "CBC ciphers on legacy TLS")
        v = results["vulnerabilities"][0]
        self.assertEqual(v["vulnerability_id"], "SSL-LUCKY13")
        self.assertEqual(v["cve"], "CVE-2013-0169")
        self.assertEqual(v["severity"], "MEDIUM")

    def test_rc4_and_3des_named_findings(self):
        from attacksurface.scanner.ssl_scanner import _add_protocol_attack

        results = {"vulnerabilities": [], "attack_grade_penalty": 0}
        _add_protocol_attack(results, "example.com", 443, "RC4", "RC4-SHA (TLSv1.2)")
        _add_protocol_attack(results, "example.com", 443, "3DES", "DES-CBC3-SHA (TLSv1.2)")

        ids = {v["vulnerability_id"] for v in results["vulnerabilities"]}
        self.assertIn("SSL-RC4-WEAKNESS", ids)
        self.assertIn("SSL-SWEET32-3DES", ids)


class VulnMapFindingTests(SimpleTestCase):
    """VulnMap: confidence / status / evidence on findings + self-healing re-scans."""

    def test_make_finding_includes_vulnmap_fields(self):
        from owasp_scanner.detectors.base import make_finding

        f = make_finding(
            "example.com", "example.com", "A02:2021 – Cryptographic Failures", 2,
            "A02-HSTS-MISSING", "MEDIUM", "CWE-523",
            "HSTS missing", "desc", "fix", "https://owasp.org/Top10/",
            "crypto/hsts-missing", confidence=0.9, status="confirmed",
            evidence="GET https://example.com returned no Strict-Transport-Security header",
        )
        self.assertEqual(f["confidence"], 0.9)
        self.assertEqual(f["status"], "confirmed")
        self.assertIn("no Strict-Transport-Security", f["evidence"])
        self.assertEqual(f["owasp_rank"], 2)

    def test_make_finding_defaults(self):
        from owasp_scanner.detectors.base import make_finding

        f = make_finding("a.com", "a.com", "A05:2021 – Security Misconfiguration", 5,
                         "A05-X", "LOW", "CWE-693", "x", "d", "r", "ref", "tpl")
        # Conservative defaults: heuristic checks are "potential" until proven
        self.assertEqual(f["confidence"], 0.7)
        self.assertEqual(f["status"], "potential")
        self.assertEqual(f["evidence"], "")

    def test_a02_redirect_evidence_captured(self):
        from unittest import mock
        from owasp_scanner.detectors.a02_cryptographic_failures import _redirect_evidence

        class FakeResp:
            status_code = 301
            headers = {"location": "https://example.com/"}

        class FakeHttp:
            def get(self, url, **kwargs):
                return FakeResp()

        ev = _redirect_evidence(FakeHttp(), "http://example.com")
        self.assertTrue(ev["redirected"])
        self.assertEqual(ev["status_code"], 301)
        self.assertEqual(ev["location"], "https://example.com/")

    def test_a02_plaintext_finding_has_confidence_and_evidence(self):
        from unittest import mock
        from owasp_scanner.detectors.a02_cryptographic_failures import detect_a02

        class FakeResp:
            status_code = 200
            headers = {"content-type": "text/html"}

        class FakeHttp:
            def get(self, url, **kwargs):
                return FakeResp()

        findings = detect_a02("example.com", "example.com",
                              ["http://example.com", "https://example.com"], FakeHttp())
        plain = [f for f in findings if f["vulnerability_id"] == "A02-PLAINTEXT-HTTP"]
        self.assertEqual(len(plain), 1)
        self.assertEqual(plain[0]["confidence"], 0.95)
        self.assertEqual(plain[0]["status"], "confirmed")
        self.assertIn("HTTP 200", plain[0]["evidence"])
        self.assertIn("without redirecting to HTTPS", plain[0]["evidence"])

    def test_a02_flapping_node_redirecting_on_retry_is_suppressed(self):
        """
        Re-verification guard: a load-balanced site where one node serves
        plaintext (200) and the rest 301->https must NOT be reported. The
        first probe catches the bad node; a later probe proves the redirect.
        """
        from owasp_scanner.detectors.a02_cryptographic_failures import detect_a02

        class RedirectResp:
            status_code = 301
            headers = {"location": "https://example.com/"}

        class PlainResp:
            status_code = 200
            headers = {"content-type": "text/html"}

        class FlappingHttp:
            def __init__(self):
                self.calls = 0

            def get(self, url, **kwargs):
                self.calls += 1
                # Probe 1 hits the bad node (plaintext 200); probe 2 hits a
                # node that correctly redirects to HTTPS.
                return PlainResp() if self.calls == 1 else RedirectResp()

        flaky = FlappingHttp()
        findings = detect_a02("example.com", "example.com",
                              ["http://example.com", "https://example.com"], flaky)
        plain = [f for f in findings if f["vulnerability_id"] == "A02-PLAINTEXT-HTTP"]
        self.assertEqual(plain, [], "flapping node must not produce A02-PLAINTEXT-HTTP")
        self.assertGreaterEqual(flaky.calls, 2)

    def test_a02_unreachable_host_is_not_reported(self):
        """
        If every probe fails to connect (no HTTP status observed), the host is
        unreachable — that is NOT evidence of a plaintext exposure.
        """
        from owasp_scanner.detectors.a02_cryptographic_failures import detect_a02

        class TimeoutResp:
            status_code = None
            headers = {}

        class TimeoutHttp:
            def get(self, url, **kwargs):
                return TimeoutResp()

        findings = detect_a02("example.com", "example.com",
                              ["http://example.com", "https://example.com"], TimeoutHttp())
        plain = [f for f in findings if f["vulnerability_id"] == "A02-PLAINTEXT-HTTP"]
        self.assertEqual(plain, [], "unreachable host must not produce A02-PLAINTEXT-HTTP")

    def test_python_scanner_skips_unreachable_plaintext(self):
        """
        run_python_vuln_scanner must not report HTTP-PLAINTEXT for an http:// URL
        that was never observed responding (status 0).
        """
        from .scanner.vulnerability_scanner import run_python_vuln_scanner

        vulns = run_python_vuln_scanner(
            "example.com",
            [{"url": "http://example.com", "headers": {}, "status_code": 0}],
        )
        plain = [v for v in vulns if v["vulnerability_id"] == "HTTP-PLAINTEXT"]
        self.assertEqual(plain, [], "unreachable host must not produce HTTP-PLAINTEXT")

    def test_python_scanner_reports_observed_plaintext(self):
        """
        A confirmed plaintext response (200 over http, no redirect) IS reported.
        """
        from unittest import mock
        from .scanner.vulnerability_scanner import run_python_vuln_scanner

        class Resp:
            status_code = 200
            headers = {}

        with mock.patch("httpx.get", return_value=Resp()):
            vulns = run_python_vuln_scanner(
                "example.com",
                [{"url": "http://example.com", "headers": {"server": "nginx/1.18.0"}, "status_code": 200}],
            )
        plain = [v for v in vulns if v["vulnerability_id"] == "HTTP-PLAINTEXT"]
        self.assertEqual(len(plain), 1)

    # Helper: run detect_a01 with a fake HTTPClient class (the detector builds
    # its own HTTPClient from .base inside _probe, so we patch the class).
    @staticmethod
    def _run_detect_a01(base_urls, body_map, not_found_body="not found"):
        from unittest import mock
        from owasp_scanner.detectors.a01_broken_access_control import detect_a01

        class FakeResp:
            def __init__(self, url, status, text):
                self.url = url
                self.status_code = status
                self.text = text
                self.headers = {}

        class FakeHttpClient:
            def __init__(self, *a, **kw):
                pass

            def get(self, url, **kwargs):
                for marker, body in body_map.items():
                    if marker in url:
                        return FakeResp(url, 200, body)
                return FakeResp(url, 404, not_found_body)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with mock.patch(
            "owasp_scanner.detectors.base.HTTPClient",
            FakeHttpClient,
        ):
            return detect_a01("example.com", "example.com", base_urls, FakeHttpClient())

    def test_a01_spa_shell_admin_route_not_reported_as_exposed(self):
        """
        A 200 on /admin that is only the SPA bootstrap shell (root div + module
        script) is NOT an exposed admin panel — client-side auth guards decide
        what renders. It becomes a low-severity 'no server guard' note instead.
        With auth markers present in the served content the note is confirmed.
        """
        SPA_BODY = (
            '<!doctype html><html><head><title>BSM</title>'
            '<script type="module" crossorigin src="/bms/assets/index-x.js"></script>'
            '</head><body><div id="root"></div>'
            '<script>localStorage.getItem("kc_access_token")</script></body></html>'
        )

        findings = self._run_detect_a01(
            ["https://example.com"],
            {"admin": SPA_BODY},
        )
        exposed = [f for f in findings if f["vulnerability_id"] == "A01-ADMIN-PANEL-EXPOSED"]
        self.assertEqual(exposed, [], "SPA shell must not be reported as exposed admin panel")
        note = [f for f in findings if f["vulnerability_id"] == "A01-ADMIN-ROUTE-NO-SERVER-GUARD"]
        self.assertEqual(len(note), 1)
        self.assertEqual(note[0]["severity"], "LOW")
        self.assertEqual(note[0]["status"], "confirmed")
        self.assertEqual(note[0]["confidence"], 0.85)
        self.assertIn("SPA shell", note[0]["evidence"])
        self.assertIn("auth guard detected", note[0]["evidence"])

    def test_a01_spa_shell_without_auth_markers_stays_potential(self):
        """
        An SPA shell with NO auth markers (no keycloak/token/login) may render
        admin content for anonymous users — the note stays potential (not
        confirmed), because client-side access control could not be verified.
        """
        SPA_BODY = (
            '<!doctype html><html><head><title>App</title>'
            '<script type="module" src="/assets/app.js"></script>'
            '</head><body><div id="root"></div></body></html>'
        )

        findings = self._run_detect_a01(
            ["https://example.com"],
            {"admin": SPA_BODY},
        )
        note = [f for f in findings if f["vulnerability_id"] == "A01-ADMIN-ROUTE-NO-SERVER-GUARD"]
        self.assertEqual(len(note), 1)
        self.assertEqual(note[0]["status"], "potential")
        self.assertEqual(note[0]["confidence"], 0.6)
        self.assertIn("NOT verified", note[0]["evidence"])

    def test_a01_server_rendered_admin_still_reported_high(self):
        """
        Regression guard: a genuinely server-rendered admin page (no SPA
        markers) returning 200 must STILL be reported as an exposed panel.
        """
        SRR_BODY = (
            '<html><head><title>Administration</title></head><body>'
            '<h1>Site Administration</h1><form><input name="user"></form>'
            '</body></html>'
        )

        findings = self._run_detect_a01(
            ["https://example.com"],
            {"admin": SRR_BODY},
        )
        exposed = [f for f in findings if f["vulnerability_id"] == "A01-ADMIN-PANEL-EXPOSED"]
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0]["severity"], "HIGH")

    def test_a01_admin_finding_is_potential_with_evidence(self):
        from owasp_scanner.detectors.base import make_finding

        # Directly construct the shape detect_a01 emits for admin panels.
        f = make_finding(
            "example.com", "example.com", "A01:2021 – Broken Access Control", 1,
            "A01-ADMIN-PANEL-EXPOSED", "HIGH", "CWE-284",
            "Potentially exposed admin/management panel at https://example.com/admin",
            "desc", "fix", "https://owasp.org/Top10/",
            "access-control/admin-panel-exposed",
            confidence=0.7, status="potential",
            evidence="GET https://example.com/admin -> HTTP 200; final page path: /admin",
        )
        self.assertEqual(f["confidence"], 0.7)
        self.assertEqual(f["status"], "potential")
        self.assertIn("HTTP 200", f["evidence"])

    def test_save_owasp_findings_persists_vulnmap_fields(self):
        from unittest import mock

        with mock.patch("attacksurface.models.VulnerabilityResult") as VR:
            vr_instance = mock.MagicMock()
            VR.objects.get_or_create.return_value = (vr_instance, True)

            from owasp_scanner.engine import save_owasp_findings

            scan = mock.MagicMock()
            scan.org_id = "1"
            findings = [{
                "vulnerability_id": "A02-HSTS-MISSING",
                "template_id": "crypto/hsts-missing",
                "subdomain": "example.com",
                "severity": "MEDIUM",
                "cwe": "CWE-523",
                "finding": "HSTS missing",
                "owasp_category": "A02:2021 – Cryptographic Failures",
                "owasp_rank": 2,
                "confidence": 0.9,
                "status": "confirmed",
                "evidence": "no HSTS header",
            }]
            saved = save_owasp_findings(scan, findings, "example.com")

        self.assertEqual(saved, 1)
        defaults = VR.objects.get_or_create.call_args.kwargs["defaults"]
        self.assertEqual(defaults["confidence"], 0.9)
        self.assertEqual(defaults["finding_status"], "confirmed")
        self.assertEqual(defaults["evidence"], "no HSTS header")

    def test_save_owasp_findings_deletes_stale_findings(self):
        from unittest import mock

        with mock.patch("attacksurface.models.VulnerabilityResult") as VR:
            vr_new = mock.MagicMock()
            VR.objects.get_or_create.return_value = (vr_new, False)

            # Two stale OWASP rows from a previous run (no longer detected)
            stale1 = mock.MagicMock()
            stale1.id = 11
            stale1.template_id = "crypto/plaintext-http"
            stale1.subdomain = "example.com"
            stale2 = mock.MagicMock()
            stale2.id = 12
            stale2.template_id = "crypto/hsts-missing"
            stale2.subdomain = "example.com"
            stale_qs = mock.MagicMock()
            stale_qs.__iter__.return_value = iter([stale1, stale2])
            VR.objects.filter.return_value = stale_qs

            from owasp_scanner.engine import save_owasp_findings

            scan = mock.MagicMock()
            scan.org_id = "1"
            findings = [{
                "vulnerability_id": "A02-HSTS-MISSING",
                "template_id": "crypto/hsts-missing",
                "subdomain": "example.com",
                "severity": "MEDIUM",
                "cwe": "CWE-523",
                "finding": "HSTS missing",
                "owasp_category": "A02:2021 – Cryptographic Failures",
                "owasp_rank": 2,
                "confidence": 0.9,
                "status": "confirmed",
                "evidence": "no HSTS header",
            }]
            save_owasp_findings(scan, findings, "example.com")

        # Only the plaintext finding is stale → only id 11 deleted
        calls = VR.objects.filter.call_args_list
        self.assertIn(
            mock.call(scan=scan, source_tool="OWASP Top 10"), calls
        )
        deleted_ids = VR.objects.filter.call_args.kwargs["id__in"]
        self.assertEqual(deleted_ids, [11])
        stale_qs.delete.assert_called_once()

    def test_save_owasp_findings_no_cleanup_when_nothing_stale(self):
        from unittest import mock

        with mock.patch("attacksurface.models.VulnerabilityResult") as VR:
            vr_new = mock.MagicMock()
            VR.objects.get_or_create.return_value = (vr_new, False)
            row = mock.MagicMock()
            row.id = 1
            row.template_id = "crypto/hsts-missing"
            row.subdomain = "example.com"
            clean_qs = mock.MagicMock()
            clean_qs.__iter__.return_value = iter([row])
            VR.objects.filter.return_value = clean_qs

            from owasp_scanner.engine import save_owasp_findings

            scan = mock.MagicMock()
            scan.org_id = "1"
            findings = [{
                "template_id": "crypto/hsts-missing",
                "subdomain": "example.com",
                "severity": "MEDIUM",
                "finding": "HSTS missing",
            }]
            save_owasp_findings(scan, findings, "example.com")

        # delete() must NOT be called when nothing is stale
        VR.objects.filter.return_value.delete.assert_not_called()
        VR.objects.filter.assert_called_once_with(
            scan=scan, source_tool="OWASP Top 10"
        )
