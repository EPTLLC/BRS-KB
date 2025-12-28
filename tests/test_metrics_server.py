#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 22:53:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for metrics server module
"""

import socket
import threading
import time
import unittest
from http.client import HTTPConnection
from io import BytesIO
from unittest.mock import MagicMock, patch

from brs_kb.metrics_server import (
    MetricsHandler,
    MetricsServer,
    start_metrics_server,
)


def get_free_port():
    """Get a free port for testing"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestMetricsHandler(unittest.TestCase):
    """Tests for MetricsHandler class"""

    def setUp(self):
        """Set up test fixtures"""
        self.handler = None

    def _create_mock_handler(self, path):
        """Create a mock handler for testing"""
        # Create mock request
        request = MagicMock()
        request.makefile.return_value = BytesIO()

        # Create mock client address
        client_address = ("127.0.0.1", 12345)

        # Create mock server
        server = MagicMock()

        # Create handler with mocked components
        with patch.object(MetricsHandler, "__init__", lambda x, *args, **kwargs: None):
            handler = MetricsHandler(request, client_address, server)
            handler.path = path
            handler.wfile = BytesIO()
            handler.requestline = f"GET {path} HTTP/1.1"
            handler.request_version = "HTTP/1.1"
            handler.client_address = client_address
            handler.headers = {}
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()
            return handler

    def test_do_get_metrics_endpoint(self):
        """Test GET /metrics endpoint"""
        handler = self._create_mock_handler("/metrics")

        with patch(
            "brs_kb.metrics_server.get_prometheus_metrics",
            return_value="# HELP test_metric Test\ntest_metric 1\n",
        ):
            handler.do_GET()

        handler.send_response.assert_called_with(200)
        handler.send_header.assert_called_with("Content-type", "text/plain; version=0.0.4")
        handler.end_headers.assert_called_once()

        # Check response body
        handler.wfile.seek(0)
        response = handler.wfile.read().decode("utf-8")
        self.assertIn("test_metric", response)

    def test_do_get_health_endpoint(self):
        """Test GET /health endpoint"""
        handler = self._create_mock_handler("/health")

        handler.do_GET()

        handler.send_response.assert_called_with(200)
        handler.send_header.assert_called_with("Content-type", "application/json")
        handler.end_headers.assert_called_once()

        # Check response body
        handler.wfile.seek(0)
        response = handler.wfile.read().decode("utf-8")
        self.assertIn("healthy", response)

    def test_do_get_not_found(self):
        """Test GET for unknown endpoint returns 404"""
        handler = self._create_mock_handler("/unknown")

        handler.do_GET()

        handler.send_response.assert_called_with(404)
        handler.end_headers.assert_called_once()

        # Check response body
        handler.wfile.seek(0)
        response = handler.wfile.read().decode("utf-8")
        self.assertEqual("Not Found", response)

    def test_do_get_metrics_with_error(self):
        """Test GET /metrics handles errors gracefully"""
        handler = self._create_mock_handler("/metrics")

        with patch(
            "brs_kb.metrics_server.get_prometheus_metrics",
            side_effect=Exception("Test error"),
        ):
            handler.do_GET()

        handler.send_response.assert_called_with(200)

        # Check error message in response
        handler.wfile.seek(0)
        response = handler.wfile.read().decode("utf-8")
        self.assertIn("Error generating metrics", response)

    def test_log_message_uses_logger(self):
        """Test that log_message uses our logger"""
        handler = self._create_mock_handler("/test")

        with patch("brs_kb.metrics_server.logger") as mock_logger:
            handler.log_message("Test message %s", "arg1")
            mock_logger.debug.assert_called_once()


class TestMetricsServer(unittest.TestCase):
    """Tests for MetricsServer class"""

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
        server = MetricsServer()
        self.assertEqual(server.port, 8000)
        self.assertEqual(server.host, "0.0.0.0")
        self.assertIsNone(server.server)
        self.assertIsNone(server.thread)

    def test_server_initialization_with_custom_values(self):
        """Test server initialization with custom port and host"""
        server = MetricsServer(port=9090, host="127.0.0.1")
        self.assertEqual(server.port, 9090)
        self.assertEqual(server.host, "127.0.0.1")

    def test_server_start_stop(self):
        """Test server start and stop"""
        self.server = MetricsServer(port=self.port, host="127.0.0.1")

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

    def test_server_double_start_warning(self):
        """Test that starting already running server logs warning"""
        self.server = MetricsServer(port=self.port, host="127.0.0.1")
        self.server.start()
        time.sleep(0.2)

        with patch("brs_kb.metrics_server.logger") as mock_logger:
            self.server.start()
            mock_logger.warning.assert_called_once()

    def test_server_is_running(self):
        """Test is_running method"""
        self.server = MetricsServer(port=self.port, host="127.0.0.1")

        # Not running initially
        self.assertFalse(self.server.is_running())

        # Running after start
        self.server.start()
        time.sleep(0.2)
        self.assertTrue(self.server.is_running())

        # Not running after stop
        self.server.stop()
        time.sleep(0.1)
        self.assertFalse(self.server.is_running())

    def test_server_responds_to_metrics_request(self):
        """Test that server responds to /metrics request"""
        self.server = MetricsServer(port=self.port, host="127.0.0.1")
        self.server.start()
        time.sleep(0.2)

        # Make HTTP request
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/metrics")
            response = conn.getresponse()

            self.assertEqual(response.status, 200)
            self.assertIn("text/plain", response.getheader("Content-type"))

            body = response.read().decode("utf-8")
            self.assertTrue(len(body) > 0)
        finally:
            conn.close()

    def test_server_responds_to_health_request(self):
        """Test that server responds to /health request"""
        self.server = MetricsServer(port=self.port, host="127.0.0.1")
        self.server.start()
        time.sleep(0.2)

        # Make HTTP request
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/health")
            response = conn.getresponse()

            self.assertEqual(response.status, 200)
            self.assertIn("application/json", response.getheader("Content-type"))

            body = response.read().decode("utf-8")
            self.assertIn("healthy", body)
        finally:
            conn.close()

    def test_server_returns_404_for_unknown_path(self):
        """Test that server returns 404 for unknown paths"""
        self.server = MetricsServer(port=self.port, host="127.0.0.1")
        self.server.start()
        time.sleep(0.2)

        # Make HTTP request
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/unknown")
            response = conn.getresponse()

            self.assertEqual(response.status, 404)
        finally:
            conn.close()


class TestStartMetricsServer(unittest.TestCase):
    """Tests for start_metrics_server function"""

    def setUp(self):
        """Set up test fixtures"""
        self.port = get_free_port()
        self.server = None

    def tearDown(self):
        """Tear down test fixtures"""
        if self.server and self.server.is_running():
            self.server.stop()
            time.sleep(0.1)

    def test_start_metrics_server_returns_server(self):
        """Test that start_metrics_server returns MetricsServer instance"""
        self.server = start_metrics_server(port=self.port, host="127.0.0.1")

        self.assertIsInstance(self.server, MetricsServer)
        self.assertTrue(self.server.is_running())

    def test_start_metrics_server_with_default_values(self):
        """Test start_metrics_server with default values"""
        # Use a different port to avoid conflicts
        port = get_free_port()
        self.server = start_metrics_server(port=port, host="127.0.0.1")

        self.assertEqual(self.server.port, port)
        self.assertEqual(self.server.host, "127.0.0.1")


class TestMetricsServerConcurrency(unittest.TestCase):
    """Tests for metrics server concurrent access"""

    def setUp(self):
        """Set up test fixtures"""
        self.port = get_free_port()
        self.server = MetricsServer(port=self.port, host="127.0.0.1")
        self.server.start()
        time.sleep(0.2)

    def tearDown(self):
        """Tear down test fixtures"""
        if self.server.is_running():
            self.server.stop()
            time.sleep(0.1)

    def test_concurrent_requests(self):
        """Test that server handles concurrent requests"""
        results = []
        errors = []

        def make_request():
            try:
                conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
                conn.request("GET", "/metrics")
                response = conn.getresponse()
                results.append(response.status)
                conn.close()
            except Exception as e:
                errors.append(str(e))

        # Create multiple threads
        threads = []
        for _ in range(10):
            t = threading.Thread(target=make_request)
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # All requests should succeed
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 10)
        self.assertTrue(all(status == 200 for status in results))


class TestMetricsServerEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling"""

    def test_server_start_on_busy_port(self):
        """Test server behavior when port is busy"""
        port = get_free_port()

        # Start first server
        server1 = MetricsServer(port=port, host="127.0.0.1")
        server1.start()
        time.sleep(0.2)

        # Try to start second server on same port
        server2 = MetricsServer(port=port, host="127.0.0.1")

        with self.assertRaises(Exception):
            server2.start()

        # Cleanup
        server1.stop()

    def test_stop_not_running_server(self):
        """Test stopping a server that was never started"""
        server = MetricsServer(port=get_free_port(), host="127.0.0.1")

        # Should not raise exception
        server.stop()
        self.assertFalse(server.is_running())


if __name__ == "__main__":
    unittest.main()
