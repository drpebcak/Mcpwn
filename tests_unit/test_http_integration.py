"""Integration tests for HTTP transport"""

import json
import multiprocessing
import subprocess
import time
import unittest

import pytest


def start_http_server(port):
    """Start HTTP MCP server in a subprocess"""
    subprocess.run(
        [
            "python3",
            "test_data/http_mcp_server.py",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class TestHTTPTransport(unittest.TestCase):
    """Test HTTP transport functionality"""

    @classmethod
    def setUpClass(cls):
        """Start HTTP server for all tests"""
        cls.port = 18081
        cls.server_process = multiprocessing.Process(
            target=start_http_server, args=(cls.port,)
        )
        cls.server_process.start()
        time.sleep(2)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        """Stop HTTP server"""
        if cls.server_process:
            cls.server_process.terminate()
            cls.server_process.join(timeout=5)
            if cls.server_process.is_alive():
                cls.server_process.kill()

    def test_http_server_starts(self):
        """Test that HTTP server is running"""
        # Note: server may have been restarted during other tests
        # Just verify we can make a request to it
        result = subprocess.run(
            [
                "python3",
                "-c",
                f"import http.client; "
                f"conn = http.client.HTTPConnection('localhost', {self.port}); "
                f"conn.request('POST', '/', body='{{}}'); "
                f"resp = conn.getresponse(); "
                f"print(resp.status)",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Server should respond (even if with an error)
        self.assertIn("200", result.stdout)

    def test_http_quick_scan(self):
        """Test quick scan via HTTP transport"""
        result = subprocess.run(
            [
                "python3",
                "mcpwn.py",
                "--quick",
                "--rce-only",
                f"http://localhost:{self.port}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Starting Mcpwn", result.stderr)
        self.assertIn("Found 2 tools", result.stderr)
        self.assertIn("Mcpwn complete", result.stderr)

    def test_http_rce_detection(self):
        """Test RCE detection via HTTP transport"""
        result = subprocess.run(
            [
                "python3",
                "mcpwn.py",
                "--rce-only",
                f"http://localhost:{self.port}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("execute_command", result.stderr)
        # Should detect some form of RCE (either pattern or timing)
        self.assertTrue(
            "RCE" in result.stderr
            or "TIMING" in result.stderr
            or "BLIND_RCE_TIMING" in result.stderr
        )

    def test_http_json_report(self):
        """Test JSON report generation via HTTP transport"""
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name

        try:
            result = subprocess.run(
                [
                    "python3",
                    "mcpwn.py",
                    "--quick",
                    "--rce-only",
                    "--output-json",
                    report_path,
                    f"http://localhost:{self.port}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0)

            # Verify JSON report was created
            with open(report_path, "r") as f:
                report = json.load(f)

            self.assertIn("tool", report)
            self.assertEqual(report["tool"], "Mcpwn")
            self.assertIn("findings", report)
            self.assertIsInstance(report["findings"], list)
        finally:
            import os

            if os.path.exists(report_path):
                os.unlink(report_path)

    def test_http_transport_flag(self):
        """Test explicit --transport http flag"""
        result = subprocess.run(
            [
                "python3",
                "mcpwn.py",
                "--transport",
                "http",
                "--quick",
                "--rce-only",
                f"http://localhost:{self.port}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Mcpwn complete", result.stderr)

    def test_http_url_validation(self):
        """Test HTTP URL is properly detected"""
        result = subprocess.run(
            [
                "python3",
                "mcpwn.py",
                "--quick",
                "--rce-only",
                f"http://localhost:{self.port}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0)
        # Should not error about command vs URL

    def test_https_url_parsing(self):
        """Test HTTPS URL is accepted (even if connection fails)"""
        # This tests URL parsing, not actual HTTPS connectivity
        result = subprocess.run(
            [
                "python3",
                "-c",
                "from core.transport_http import HTTPTransport; "
                "t = HTTPTransport('https://example.com:443/mcp'); "
                "print(t.scheme, t.host, t.port, t.path)",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("https example.com 443 /mcp", result.stdout)


class TestHTTPTransportUnit(unittest.TestCase):
    """Unit tests for HTTP transport (no server needed)"""

    def test_http_transport_import(self):
        """Test HTTP transport can be imported"""
        from core.transport_http import HTTPTransport

        self.assertIsNotNone(HTTPTransport)

    def test_http_transport_initialization(self):
        """Test HTTP transport initialization"""
        from core.transport_http import HTTPTransport

        transport = HTTPTransport("http://localhost:8080/mcp")
        self.assertEqual(transport.scheme, "http")
        self.assertEqual(transport.host, "localhost")
        self.assertEqual(transport.port, 8080)
        self.assertEqual(transport.path, "/mcp")

    def test_http_transport_default_port(self):
        """Test HTTP transport uses default ports"""
        from core.transport_http import HTTPTransport

        transport_http = HTTPTransport("http://localhost")
        self.assertEqual(transport_http.port, 80)

        transport_https = HTTPTransport("https://localhost")
        self.assertEqual(transport_https.port, 443)

    def test_http_transport_invalid_scheme(self):
        """Test HTTP transport rejects invalid schemes"""
        from core.transport_http import HTTPTransport

        with self.assertRaises(ValueError):
            HTTPTransport("ftp://localhost:8080")

    def test_http_transport_path_default(self):
        """Test HTTP transport uses default path"""
        from core.transport_http import HTTPTransport

        transport = HTTPTransport("http://localhost:8080")
        self.assertEqual(transport.path, "/")


if __name__ == "__main__":
    unittest.main()
