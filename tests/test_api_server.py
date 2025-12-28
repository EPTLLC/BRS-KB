#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 22:53:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for API server module
"""

import json
import socket
import time
import unittest
from http.client import HTTPConnection
from typing import Optional

from brs_kb.api_server import APIServer, start_api_server


def get_free_port():
    """Get a free port for testing"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestAPIServer(unittest.TestCase):
    """Tests for APIServer class"""

    def setUp(self):
        """Set up test fixtures"""
        self.port = get_free_port()
        self.server = None

    def tearDown(self):
        """Tear down test fixtures"""
        if self.server and self.server.is_running():
            self.server.stop()
            time.sleep(0.1)

    def test_server_initialization(self):
        """Test server initialization with default values"""
        server = APIServer()
        self.assertEqual(server.port, 8080)
        self.assertEqual(server.host, "0.0.0.0")
        self.assertIsNone(server.server)
        self.assertIsNone(server.thread)

    def test_server_initialization_with_custom_values(self):
        """Test server initialization with custom port and host"""
        server = APIServer(port=9090, host="127.0.0.1")
        self.assertEqual(server.port, 9090)
        self.assertEqual(server.host, "127.0.0.1")

    def test_server_start_stop(self):
        """Test server start and stop"""
        self.server = APIServer(port=self.port, host="127.0.0.1")

        # Server should not be running initially
        self.assertFalse(self.server.is_running())

        # Start server
        self.server.start()
        time.sleep(0.2)

        # Server should be running
        self.assertTrue(self.server.is_running())

        # Stop server
        self.server.stop()
        time.sleep(0.1)

        # Server should not be running
        self.assertFalse(self.server.is_running())


class TestAPIEndpoints(unittest.TestCase):
    """Tests for API endpoints"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures once for all tests"""
        cls.port = get_free_port()
        cls.server = APIServer(port=cls.port, host="127.0.0.1")
        cls.server.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        """Tear down test fixtures"""
        if cls.server and cls.server.is_running():
            cls.server.stop()
            time.sleep(0.1)

    def _make_request(self, method: str, path: str, body: Optional[dict] = None) -> tuple:
        """Make HTTP request and return status and response body"""
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            headers = {}
            body_str = None
            if body:
                body_str = json.dumps(body)
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(body_str))

            conn.request(method, path, body=body_str, headers=headers)
            response = conn.getresponse()
            data = response.read().decode("utf-8")
            return response.status, json.loads(data) if data else {}
        finally:
            conn.close()

    def test_health_endpoint(self):
        """Test GET /api/health"""
        status, data = self._make_request("GET", "/api/health")

        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "brs-kb-api")

    def test_info_endpoint(self):
        """Test GET /api/info"""
        status, data = self._make_request("GET", "/api/info")

        self.assertEqual(status, 200)
        self.assertIn("version", data)
        self.assertIn("total_contexts", data)
        self.assertIn("total_payloads", data)

    def test_list_contexts_endpoint(self):
        """Test GET /api/contexts"""
        status, data = self._make_request("GET", "/api/contexts")

        self.assertEqual(status, 200)
        self.assertIn("contexts", data)
        self.assertIn("total", data)
        self.assertGreater(data["total"], 0)

        # Check context structure
        if data["contexts"]:
            ctx = data["contexts"][0]
            self.assertIn("id", ctx)
            self.assertIn("title", ctx)
            self.assertIn("severity", ctx)
            self.assertIn("cvss_score", ctx)

    def test_get_context_endpoint(self):
        """Test GET /api/contexts/<id>"""
        status, data = self._make_request("GET", "/api/contexts/html_content")

        self.assertEqual(status, 200)
        self.assertEqual(data["id"], "html_content")
        self.assertIn("title", data)
        self.assertIn("description", data)
        self.assertIn("attack_vector", data)
        self.assertIn("remediation", data)
        self.assertIn("severity", data)
        self.assertIn("cvss_score", data)

    def test_get_context_default_fallback(self):
        """Test GET /api/contexts/<id> with non-existent context returns default"""
        status, data = self._make_request("GET", "/api/contexts/nonexistent_context")

        # BRS-KB returns default context for unknown contexts
        self.assertEqual(status, 200)
        # Should return default context info (generic XSS)
        self.assertIn("title", data)

    def test_list_payloads_endpoint(self):
        """Test GET /api/payloads"""
        status, data = self._make_request("GET", "/api/payloads")

        self.assertEqual(status, 200)
        self.assertIn("payloads", data)
        self.assertIn("total", data)
        self.assertIn("offset", data)
        self.assertIn("limit", data)

    def test_list_payloads_by_context(self):
        """Test GET /api/payloads?context=html_content"""
        status, data = self._make_request("GET", "/api/payloads?context=html_content")

        self.assertEqual(status, 200)
        self.assertIn("payloads", data)

        # All payloads should contain html_content in contexts
        for payload in data["payloads"]:
            self.assertIn("html_content", payload["contexts"])

    def test_list_payloads_by_severity(self):
        """Test GET /api/payloads?severity=critical"""
        status, data = self._make_request("GET", "/api/payloads?severity=critical")

        self.assertEqual(status, 200)
        self.assertIn("payloads", data)

        # All payloads should have critical severity
        for payload in data["payloads"]:
            self.assertEqual(payload["severity"], "critical")

    def test_search_payloads_endpoint(self):
        """Test GET /api/payloads/search?q=script"""
        status, data = self._make_request("GET", "/api/payloads/search?q=script")

        self.assertEqual(status, 200)
        self.assertIn("results", data)
        self.assertIn("query", data)
        self.assertEqual(data["query"], "script")

        # Results should have relevance scores
        for result in data["results"]:
            self.assertIn("relevance_score", result)

    def test_search_payloads_no_query(self):
        """Test GET /api/payloads/search without query"""
        status, data = self._make_request("GET", "/api/payloads/search")

        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_analyze_payload_get(self):
        """Test GET /api/analyze?payload=<script>"""
        payload = "<script>alert(1)</script>"
        status, data = self._make_request("GET", f"/api/analyze?payload={payload}")

        self.assertEqual(status, 200)
        self.assertIn("contexts", data)
        self.assertIn("severity", data)

    def test_analyze_payload_post(self):
        """Test POST /api/analyze"""
        status, data = self._make_request(
            "POST", "/api/analyze", {"payload": "<script>alert(1)</script>"}
        )

        self.assertEqual(status, 200)
        self.assertIn("contexts", data)
        self.assertIn("severity", data)

    def test_analyze_payload_post_ml_features(self):
        """Test POST /api/analyze with ML features"""
        status, data = self._make_request(
            "POST", "/api/analyze", {"payload": "<script>alert(1)</script>", "ml_features": True}
        )

        self.assertEqual(status, 200)
        self.assertIn("contexts", data)
        self.assertIn("features", data)

    def test_analyze_payload_no_payload(self):
        """Test POST /api/analyze without payload"""
        status, data = self._make_request("POST", "/api/analyze", {})

        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_get_defenses_endpoint(self):
        """Test GET /api/defenses?context=html_content"""
        status, data = self._make_request("GET", "/api/defenses?context=html_content")

        self.assertEqual(status, 200)
        self.assertIn("context", data)
        self.assertIn("defenses", data)
        self.assertEqual(data["context"], "html_content")

    def test_get_defenses_no_context(self):
        """Test GET /api/defenses without context"""
        status, data = self._make_request("GET", "/api/defenses")

        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_stats_endpoint(self):
        """Test GET /api/stats"""
        status, data = self._make_request("GET", "/api/stats")

        self.assertEqual(status, 200)
        self.assertIn("total_contexts", data)
        self.assertIn("total_payloads", data)
        self.assertIn("severity_distribution", data)
        self.assertIn("context_coverage", data)

    def test_not_found_endpoint(self):
        """Test unknown endpoint returns 404"""
        status, data = self._make_request("GET", "/api/unknown")

        self.assertEqual(status, 404)
        self.assertIn("error", data)

    def test_cors_headers(self):
        """Test CORS headers are present"""
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/api/health")
            response = conn.getresponse()

            self.assertEqual(response.getheader("Access-Control-Allow-Origin"), "*")
            self.assertIn("GET", response.getheader("Access-Control-Allow-Methods"))
        finally:
            conn.close()

    def test_options_preflight(self):
        """Test OPTIONS preflight request"""
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("OPTIONS", "/api/health")
            response = conn.getresponse()

            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Access-Control-Allow-Origin"), "*")
        finally:
            conn.close()


class TestStartAPIServer(unittest.TestCase):
    """Tests for start_api_server function"""

    def setUp(self):
        """Set up test fixtures"""
        self.port = get_free_port()
        self.server = None

    def tearDown(self):
        """Tear down test fixtures"""
        if self.server and self.server.is_running():
            self.server.stop()
            time.sleep(0.1)

    def test_start_api_server_returns_server(self):
        """Test that start_api_server returns APIServer instance"""
        self.server = start_api_server(port=self.port, host="127.0.0.1")

        self.assertIsInstance(self.server, APIServer)
        self.assertTrue(self.server.is_running())

    def test_start_api_server_with_default_values(self):
        """Test start_api_server with default port override"""
        self.server = start_api_server(port=self.port, host="127.0.0.1")

        self.assertEqual(self.server.port, self.port)
        self.assertEqual(self.server.host, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
