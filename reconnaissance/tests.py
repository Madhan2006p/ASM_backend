import json
from unittest.mock import ANY, MagicMock, patch

from rest_framework.test import APITestCase

from .models import DiscoveredDomain, ReconEndpoint, ToolOutput
from .services.email_security_scanner import parse_smtp_starttls
from .services.nmap_scanner import parse_nmap


class RunScanViewTests(APITestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user(username="testuser", password="testpass123")
        self.client.force_authenticate(user=self.user)

    def test_run_scan_includes_cyber_team_tools(self):
        with (
            patch("reconnaissance.views.run_subfinder", return_value=subdomain_result("a.example.com", "b.example.com")),
            patch("reconnaissance.views.run_assetfinder", return_value=subdomain_result("b.example.com", "c.example.com")),
            patch("reconnaissance.views.run_findomain", return_value=subdomain_result("d.example.com")),
            patch("reconnaissance.views.run_gau", return_value=endpoint_result()),
            patch("reconnaissance.views.run_naabu", return_value=open_port_result()),
            patch("reconnaissance.views.run_email_security_scan", return_value=email_security_result()),
            patch(
                "reconnaissance.views.run_httpx",
                return_value={
                    "raw_output": "https://a.example.com\n",
                    "parsed_output": {
                        "total_live_hosts": 1,
                        "live_hosts": [{"url": "https://a.example.com"}],
                    },
                },
            ),
            patch(
                "reconnaissance.views.run_nmap",
                return_value={
                    "raw_output": "<nmaprun />",
                    "parsed_output": {
                        "total_hosts": 1,
                        "total_ports": 1,
                        "targets_scanned": ["a.example.com"],
                        "hosts": [{"address": "1.1.1.1", "hostname": "a.example.com", "ports": []}],
                        "ports": [{"host": "1.1.1.1", "port": "443", "state": "open"}],
                    },
                },
            ),
            patch(
                "reconnaissance.views.run_nuclei",
                return_value={
                    "raw_output": "{}",
                    "parsed_output": {
                        "total_vulnerabilities": 1,
                        "targets_scanned": ["https://a.example.com"],
                        "vulnerabilities": [
                            {
                                "template_id": "tech-detect",
                                "name": "Technology Detection",
                                "severity": "info",
                                "target": "https://a.example.com",
                            }
                        ],
                    },
                },
            ),
        ):
            response = self.client.post(
                "/api/recon/run-scan/",
                {"target": "https://Example.com/login"},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["target"], "example.com")
        self.assertIn("findomain", response.data)
        self.assertIn("email_security", response.data)
        self.assertEqual(response.data["public_assets"]["total_discovered_subdomains"], 4)

        tool_names = set(ToolOutput.objects.values_list("tool_name", flat=True))
        self.assertEqual(
            tool_names,
            {
                "subfinder",
                "assetfinder",
                "findomain",
                "gau",
                "naabu",
                "httpx",
                "nmap",
                "nuclei",
                "email_security",
            },
        )
        self.assertEqual(DiscoveredDomain.objects.count(), 4)
        self.assertEqual(ReconEndpoint.objects.count(), 1)


class NmapParserTests(APITestCase):
    def test_parse_nmap_extracts_hosts_ports_and_scripts(self):
        parsed = parse_nmap(
            """
            <nmaprun>
              <host>
                <status state="up" />
                <address addr="203.0.113.10" addrtype="ipv4" />
                <hostnames>
                  <hostname name="mail.example.com" />
                </hostnames>
                <os>
                  <osmatch name="Linux 5.x" />
                </os>
                <ports>
                  <port protocol="tcp" portid="25">
                    <state state="open" />
                    <service name="smtp" product="Postfix" version="3.6" />
                    <script id="smtp-open-relay" output="Server doesn't seem to be an open relay" />
                  </port>
                </ports>
              </host>
            </nmaprun>
            """
        )

        self.assertEqual(len(parsed["hosts"]), 1)
        self.assertEqual(len(parsed["ports"]), 1)
        self.assertEqual(parsed["hosts"][0]["hostname"], "mail.example.com")
        self.assertEqual(parsed["hosts"][0]["os_matches"], ["Linux 5.x"])
        self.assertEqual(parsed["ports"][0]["service"], "smtp")
        self.assertEqual(parsed["ports"][0]["scripts"][0]["id"], "smtp-open-relay")


class WaybackurlsScannerTests(APITestCase):
    """Tests for the waybackurls scanner module."""

    @patch("reconnaissance.services.waybackurls_scanner.resolve_executable", return_value=None)
    def test_run_waybackurls_executable_not_found(self, mock_resolve):
        from .services.waybackurls_scanner import run_waybackurls

        result = run_waybackurls("example.com")

        self.assertEqual(result["raw_output"], "")
        self.assertEqual(result["parsed_output"]["total_urls"], 0)
        self.assertEqual(result["parsed_output"]["urls"], [])
        self.assertIn("not found", result["parsed_output"]["error"].lower())

    @patch("reconnaissance.services.waybackurls_scanner.resolve_executable", return_value="/usr/bin/waybackurls")
    @patch("reconnaissance.services.waybackurls_scanner.run_command")
    def test_run_waybackurls_success(self, mock_run, mock_resolve):
        from .services.waybackurls_scanner import run_waybackurls

        mock_run.return_value = {
            "stdout": "https://example.com/page1\nhttps://example.com/page2\n",
            "stderr": "",
            "returncode": 0,
            "error": None,
            "execution_time": 5.0,
        }

        result = run_waybackurls("example.com")

        self.assertEqual(result["parsed_output"]["total_urls"], 2)
        self.assertEqual(len(result["parsed_output"]["urls"]), 2)
        self.assertEqual(result["parsed_output"]["urls"][0]["url"], "https://example.com/page1")
        self.assertEqual(result["parsed_output"]["urls"][1]["url"], "https://example.com/page2")

    @patch("reconnaissance.services.waybackurls_scanner.resolve_executable", return_value="/usr/bin/waybackurls")
    @patch("reconnaissance.services.waybackurls_scanner.run_command")
    def test_parse_waybackurls_deduplicates(self, mock_run, mock_resolve):
        from .services.waybackurls_scanner import run_waybackurls

        mock_run.return_value = {
            "stdout": "https://example.com/page1\nhttps://example.com/page1\nhttps://example.com/page2\n",
            "stderr": "",
            "returncode": 0,
            "error": None,
            "execution_time": 3.0,
        }

        result = run_waybackurls("example.com")

        self.assertEqual(result["parsed_output"]["total_urls"], 2)
        self.assertEqual(len(result["parsed_output"]["urls"]), 2)

    def test_parse_waybackurls_isolated(self):
        from .services.waybackurls_scanner import parse_waybackurls

        output = "https://example.com/a\nhttps://example.com/b\n\n"
        urls = parse_waybackurls(output)

        self.assertEqual(len(urls), 2)
        self.assertEqual(urls[0]["url"], "https://example.com/a")


class WapitiScannerTests(APITestCase):
    """Tests for the wapiti scanner module."""

    @patch("reconnaissance.services.wapiti_scanner.resolve_executable", return_value=None)
    def test_run_wapiti_executable_not_found(self, mock_resolve):
        from .services.wapiti_scanner import run_wapiti

        result = run_wapiti("example.com")

        self.assertEqual(result["parsed_output"]["total_vulnerabilities"], 0)
        self.assertEqual(result["parsed_output"]["vulnerabilities"], [])
        self.assertIn("not found", result["parsed_output"]["error"].lower())

    @patch("reconnaissance.services.wapiti_scanner.resolve_executable", return_value="/usr/bin/wapiti")
    @patch("reconnaissance.services.wapiti_scanner.run_command")
    @patch("reconnaissance.services.wapiti_scanner.shutil.rmtree")
    def test_run_wapiti_with_empty_report(self, mock_rmtree, mock_run, mock_resolve):
        import tempfile
        from pathlib import Path
        from .services.wapiti_scanner import run_wapiti

        mock_run.return_value = {
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "error": None,
            "execution_time": 10.0,
        }

        # Create empty temp dir with no report.json
        tmpdir = tempfile.mkdtemp(prefix="wapiti_test_")
        try:
            with patch("reconnaissance.services.wapiti_scanner.tempfile.mkdtemp", return_value=tmpdir):
                result = run_wapiti("https://example.com")

                self.assertEqual(result["parsed_output"]["total_vulnerabilities"], 0)
                self.assertEqual(result["parsed_output"]["vulnerabilities"], [])
                self.assertIn("https://example.com", result["parsed_output"]["targets_scanned"])
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_run_wapiti_no_valid_urls(self):
        from .services.wapiti_scanner import run_wapiti

        result = run_wapiti("")

        self.assertEqual(result["parsed_output"]["total_vulnerabilities"], 0)
        self.assertIn("error", result["parsed_output"])

    def test_run_wapiti_string_target_converted_to_list(self):
        from .services.wapiti_scanner import run_wapiti

        # When executable is not found, string target should still be handled gracefully
        result = run_wapiti("")
        self.assertEqual(result["parsed_output"]["total_vulnerabilities"], 0)

    @patch("reconnaissance.services.wapiti_scanner.resolve_executable", return_value="/usr/bin/wapiti")
    @patch("reconnaissance.services.wapiti_scanner.run_command")
    @patch("reconnaissance.services.wapiti_scanner.shutil.rmtree")
    def test_run_wapiti_parses_vulnerabilities(self, mock_rmtree, mock_run, mock_resolve):
        from pathlib import Path
        import tempfile
        from .services.wapiti_scanner import run_wapiti

        mock_run.return_value = {
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "error": None,
            "execution_time": 15.0,
        }

        report_data = {
            "vulnerabilities": {
                "sql_injection": [
                    {"info": "SQL injection in login", "level": "3", "module": "sql"},
                ],
                "xss": [
                    {"info": "Reflected XSS in search", "level": "2", "module": "xss"},
                ],
            }
        }

        # Create a real temp directory with a real JSON report file
        tmpdir = tempfile.mkdtemp(prefix="wapiti_test_")
        try:
            report_path = Path(tmpdir) / "report.json"
            report_path.write_text(json.dumps(report_data))

            with patch("reconnaissance.services.wapiti_scanner.tempfile.mkdtemp", return_value=tmpdir):
                result = run_wapiti("https://example.com")

                self.assertEqual(result["parsed_output"]["total_vulnerabilities"], 2)
                vulns = result["parsed_output"]["vulnerabilities"]
                self.assertEqual(len(vulns), 2)

                # Check SQL injection vuln
                sql_vuln = next(v for v in vulns if v["template_id"] == "sql_injection")
                self.assertEqual(sql_vuln["severity"], "HIGH")
                self.assertEqual(sql_vuln["source_tool"], "Wapiti")

                # Check XSS vuln
                xss_vuln = next(v for v in vulns if v["template_id"] == "xss")
                self.assertEqual(xss_vuln["severity"], "MEDIUM")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class WappalyzerScannerTests(APITestCase):
    """Tests for the wappalyzer scanner module."""

    def test_format_output_with_results(self):
        from .services.wappalyzer_scanner import _format_output

        results = [
            {
                "domain": "example.com",
                "url": "https://example.com",
                "technologies": ["Nginx", "React", "PHP"],
            },
            {
                "domain": "test.example.com",
                "url": "https://test.example.com",
                "technologies": ["Nginx", "Python"],
            },
        ]

        output = _format_output(results)

        self.assertEqual(output["parsed_output"]["total_detected"], 2)
        self.assertEqual(len(output["parsed_output"]["hosts"]), 2)
        # Nginx appears in both hosts
        self.assertEqual(output["parsed_output"]["technologies_summary"]["Nginx"], 2)
        self.assertEqual(output["parsed_output"]["technologies_summary"]["React"], 1)

    def test_format_output_empty(self):
        from .services.wappalyzer_scanner import _format_output

        output = _format_output([])

        self.assertEqual(output["parsed_output"]["total_detected"], 0)
        self.assertEqual(output["parsed_output"]["hosts"], [])
        self.assertEqual(output["parsed_output"]["technologies_summary"], {})

    @patch("reconnaissance.services.wappalyzer_scanner._run_fallback_tech_detection")
    @patch("reconnaissance.services.wappalyzer_scanner.WAPPALYZER_AVAILABLE", False)
    def test_run_wappalyzer_uses_fallback_when_library_unavailable(self, mock_fallback):
        from .services.wappalyzer_scanner import run_wappalyzer

        mock_fallback.return_value = {
            "raw_output": "[]",
            "parsed_output": {"total_detected": 0, "hosts": [], "technologies_summary": {}},
        }

        run_wappalyzer("example.com")
        mock_fallback.assert_called_once_with(["example.com"])

    def test_run_wappalyzer_fallback_detection(self):
        from .services.wappalyzer_scanner import run_wappalyzer

        # httpx is imported inside _run_fallback_tech_detection, so patch the global httpx.Client
        with patch("reconnaissance.services.wappalyzer_scanner.WAPPALYZER_AVAILABLE", False):
            with patch("httpx.Client") as mock_client:
                mock_instance = MagicMock()
                mock_instance.__enter__.return_value = mock_instance
                resp_mock = MagicMock()
                resp_mock.headers = {}
                resp_mock.text = "<html><head><title>Test</title></head></html>"
                resp_mock.status_code = 200
                mock_instance.get.return_value = resp_mock
                mock_client.return_value = mock_instance

                result = run_wappalyzer("https://example.com")

                self.assertIn("parsed_output", result)
                self.assertIn("total_detected", result["parsed_output"])


class DirsearchScannerTests(APITestCase):
    """Tests for the dirsearch scanner module."""

    @patch("reconnaissance.services.dirsearch_scanner.resolve_executable", return_value=None)
    @patch("reconnaissance.services.dirsearch_scanner.httpx.Client")
    def test_run_dirsearch_fallback_python(self, mock_client, mock_resolve):
        from .services.dirsearch_scanner import run_dirsearch

        mock_instance = MagicMock()
        mock_instance.__enter__.return_value = mock_instance
        mock_client.return_value = mock_instance

        resp_mock = MagicMock()
        resp_mock.status_code = 200
        resp_mock.headers = {"content-type": "text/html"}
        resp_mock.content = b"<html></html>"
        mock_instance.get.return_value = resp_mock

        result = run_dirsearch("https://example.com")

        self.assertIn("parsed_output", result)
        self.assertIn("total_directories", result["parsed_output"])
        # Should note it's a Python fallback
        self.assertIn("note", result["parsed_output"])

    @patch("reconnaissance.services.dirsearch_scanner.resolve_executable", return_value=None)
    @patch("reconnaissance.services.dirsearch_scanner.httpx.Client")
    def test_run_dirsearch_python_fallback_empty(self, mock_client, mock_resolve):
        from .services.dirsearch_scanner import run_dirsearch

        mock_instance = MagicMock()
        mock_instance.__enter__.return_value = mock_instance
        mock_client.return_value = mock_instance

        # All 404s
        resp_mock = MagicMock()
        resp_mock.status_code = 404
        mock_instance.get.return_value = resp_mock

        result = run_dirsearch(["https://example.com"])

        self.assertEqual(result["parsed_output"]["total_directories"], 0)
        self.assertEqual(result["parsed_output"]["directories"], [])

    @patch("reconnaissance.services.dirsearch_scanner.resolve_executable", return_value="/usr/bin/dirsearch")
    @patch("reconnaissance.services.dirsearch_scanner.run_command")
    @patch("reconnaissance.services.dirsearch_scanner.tempfile.NamedTemporaryFile")
    @patch("reconnaissance.services.dirsearch_scanner.Path")
    def test_run_dirsearch_binary_with_results(self, mock_path, mock_tempfile, mock_run, mock_resolve):
        from .services.dirsearch_scanner import run_dirsearch

        mock_run.return_value = {
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "error": None,
            "execution_time": 10.0,
        }

        # Create a mock temp file
        mock_temp = MagicMock()
        mock_temp.name = "/tmp/dirsearch_out.json"
        mock_tempfile.return_value.__enter__.return_value = mock_temp

        # Mock the output file content (dirsearch JSON format)
        report_data = {
            "results": [
                {"url": "https://example.com/admin", "status": 200, "content-type": "text/html", "content-length": 1024},
                {"url": "https://example.com/login", "status": 200, "content-type": "text/html", "content-length": 2048},
            ]
        }
        mock_file = MagicMock()
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = json.dumps(report_data)
        mock_path.return_value = mock_file

        result = run_dirsearch("https://example.com")

        self.assertEqual(result["parsed_output"]["total_directories"], 2)
        self.assertEqual(len(result["parsed_output"]["directories"]), 2)
        self.assertEqual(result["parsed_output"]["directories"][0]["url"], "https://example.com/admin")
        self.assertEqual(result["parsed_output"]["directories"][0]["status"], 200)

    def test_run_dirsearch_string_input(self):
        from .services.dirsearch_scanner import run_dirsearch

        with patch("reconnaissance.services.dirsearch_scanner.resolve_executable", return_value=None):
            with patch("reconnaissance.services.dirsearch_scanner.httpx.Client") as mock_client:
                mock_instance = MagicMock()
                mock_instance.__enter__.return_value = mock_instance
                resp_mock = MagicMock()
                resp_mock.status_code = 200
                resp_mock.headers = {"content-type": "application/json"}
                resp_mock.content = b"{}"
                mock_instance.get.return_value = resp_mock
                mock_client.return_value = mock_instance

                result = run_dirsearch("example.com")

                self.assertIn("parsed_output", result)
                # Should have at least one found directory
                self.assertGreaterEqual(result["parsed_output"]["total_directories"], 0)


class WhatwebScannerTests(APITestCase):
    """Tests for the whatweb scanner module."""

    def test_probe_and_detect_nginx_server(self):
        from .services.whatweb_scanner import probe_and_detect

        with patch("reconnaissance.services.whatweb_scanner.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.__enter__.return_value = mock_instance
            resp_mock = MagicMock()
            resp_mock.headers = {"Server": "nginx/1.18.0", "Content-Type": "text/html"}
            resp_mock.text = "<html><head><title>Welcome</title></head><body>Hello</body></html>"
            resp_mock.status_code = 200
            mock_instance.get.return_value = resp_mock
            mock_client.return_value = mock_instance

            result = probe_and_detect("https://example.com")

            self.assertIsNotNone(result)
            self.assertIn("Nginx", result["technologies"])
            self.assertEqual(result["host"], "example.com")
            self.assertEqual(result["status_code"], 200)

    def test_probe_and_detect_wordpress_html(self):
        from .services.whatweb_scanner import probe_and_detect

        with patch("reconnaissance.services.whatweb_scanner.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.__enter__.return_value = mock_instance
            resp_mock = MagicMock()
            resp_mock.headers = {"Server": "Apache", "Content-Type": "text/html"}
            resp_mock.text = (
                "<html><head><title>My WP Site</title>"
                '<link rel="stylesheet" href="/wp-content/themes/style.css" />'
                "</head><body>Hello</body></html>"
            )
            resp_mock.status_code = 200
            mock_instance.get.return_value = resp_mock
            mock_client.return_value = mock_instance

            result = probe_and_detect("https://example.com/blog")

            self.assertIsNotNone(result)
            self.assertIn("WordPress", result["technologies"])
            self.assertIn("Apache HTTP Server", result["technologies"])

    def test_probe_and_detect_cookie_based(self):
        from .services.whatweb_scanner import probe_and_detect

        with patch("reconnaissance.services.whatweb_scanner.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.__enter__.return_value = mock_instance
            resp_mock = MagicMock()
            resp_mock.headers = {
                "Server": "nginx",
                "Content-Type": "text/html",
                "Set-Cookie": "PHPSESSID=abc123; Path=/",
            }
            resp_mock.text = "<html><body>Hello</body></html>"
            resp_mock.status_code = 200
            mock_instance.get.return_value = resp_mock
            mock_client.return_value = mock_instance

            result = probe_and_detect("https://example.com")

            self.assertIsNotNone(result)
            self.assertIn("PHP", result["technologies"])
            self.assertIn("Nginx", result["technologies"])

    def test_probe_and_detect_no_tech(self):
        from .services.whatweb_scanner import probe_and_detect

        with patch("reconnaissance.services.whatweb_scanner.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.__enter__.return_value = mock_instance
            resp_mock = MagicMock()
            resp_mock.headers = {"Content-Type": "text/plain"}
            resp_mock.text = "Just plain text here"
            resp_mock.status_code = 200
            mock_instance.get.return_value = resp_mock
            mock_client.return_value = mock_instance

            result = probe_and_detect("https://example.com/text")

            self.assertIsNone(result)

    def test_probe_and_detect_connection_error(self):
        from .services.whatweb_scanner import probe_and_detect

        with patch("reconnaissance.services.whatweb_scanner.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.__enter__.return_value = mock_instance
            mock_instance.get.side_effect = Exception("Connection refused")
            mock_client.return_value = mock_instance

            result = probe_and_detect("https://example.com")

            self.assertIsNone(result)

    def test_run_whatweb_scan_empty_error(self):
        from .services.whatweb_scanner import run_whatweb_scan

        with patch("reconnaissance.services.whatweb_scanner.run_whatweb", side_effect=Exception("Scan failed")):
            result = run_whatweb_scan("example.com")

            self.assertIn("error", result["parsed_output"])
            self.assertEqual(result["parsed_output"]["total_detected"], 0)

    def test_run_whatweb_scan_successful(self):
        from .services.whatweb_scanner import run_whatweb_scan

        mock_results = [
            {
                "url": "https://example.com",
                "host": "example.com",
                "technologies": ["Nginx", "React"],
                "categories": {"Web Server": ["Nginx"], "JavaScript Framework": ["React"]},
                "title": "Test",
                "status_code": 200,
                "headers": {"Server": "nginx"},
            },
        ]

        with patch("reconnaissance.services.whatweb_scanner.run_whatweb", return_value=mock_results):
            result = run_whatweb_scan("example.com")

            self.assertEqual(result["parsed_output"]["total_detected"], 1)
            self.assertEqual(len(result["parsed_output"]["hosts"]), 1)
            self.assertEqual(result["parsed_output"]["technologies_summary"]["Nginx"], 1)
            self.assertEqual(result["parsed_output"]["technologies_summary"]["React"], 1)

    def test_run_whatweb_string_to_list(self):
        from .services.whatweb_scanner import run_whatweb

        with patch("reconnaissance.services.whatweb_scanner.probe_and_detect", return_value=None):
            results = run_whatweb("example.com")
            self.assertEqual(results, [])


class EmailSecurityParserTests(APITestCase):
    def test_parse_smtp_starttls_extracts_certificate_metadata(self):
        parsed = parse_smtp_starttls(
            """
            subject=CN = mail.example.com
            issuer=C = US, O = Example CA
            Protocol  : TLSv1.3
            Cipher    : TLS_AES_256_GCM_SHA384
            start date: May 20 00:00:00 2026 GMT
            expire date: Jun 20 23:59:59 2027 GMT
            Verify return code: 0 (ok)
            """
        )

        self.assertEqual(parsed["subject"], "CN = mail.example.com")
        self.assertEqual(parsed["issuer"], "C = US, O = Example CA")
        self.assertEqual(parsed["protocol"], "TLSv1.3")
        self.assertEqual(parsed["cipher"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(parsed["verify_return_code"], "0 (ok)")


def subdomain_result(*subdomains):
    return {
        "raw_output": "\n".join(subdomains),
        "parsed_output": {
            "total_subdomains": len(subdomains),
            "subdomains": [{"subdomain": value} for value in subdomains],
        },
    }


def endpoint_result(*urls):
    return {
        "raw_output": "\n".join(urls),
        "parsed_output": {
            "total_endpoints": len(urls),
            "endpoints": [{"url": value} for value in urls],
        },
    }


def open_port_result(*ports):
    return {
        "raw_output": "\n".join(ports),
        "parsed_output": {
            "total_open_ports": len(ports),
            "open_ports": [],
        },
    }


def email_security_result():
    return {
        "domain": "example.com",
        "dns_backend": "dnspython",
        "root_txt": ['"v=spf1 include:_spf.example.com ~all"'],
        "spf": ['"v=spf1 include:_spf.example.com ~all"'],
        "dmarc": ['"v=DMARC1; p=reject"'],
        "mx": ["10 mail.example.com."],
        "dkim_selector1": [],
        "dkim_default": [],
        "smtp_hosts": ["mail.example.com"],
        "smtp_port_scan": {"total_hosts": 1, "total_ports": 1, "hosts": [], "ports": []},
        "smtp_open_relay": {"total_hosts": 1, "total_ports": 1, "hosts": [], "ports": []},
        "smtp_starttls": {"host": "mail.example.com", "protocol": "TLSv1.3"},
    }
