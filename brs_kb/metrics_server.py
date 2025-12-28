#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Metrics HTTP server for Prometheus scraping
Provides /metrics endpoint for Prometheus
"""

import http.server
import socketserver
import threading
from typing import Optional

from brs_kb.metrics import get_logger, get_prometheus_metrics


logger = get_logger("brs_kb.metrics_server")


class MetricsHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler for metrics endpoint"""

    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-type", "text/plain; version=0.0.4")
            self.end_headers()

            try:
                metrics = get_prometheus_metrics()
                self.wfile.write(metrics.encode("utf-8"))
            except Exception as e:
                logger.error("Error generating metrics: %s", e, exc_info=True)
                self.wfile.write(f"# Error generating metrics: {e}\n".encode())

        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.debug("HTTP %s", format % args)


class MetricsServer:
    """HTTP server for Prometheus metrics"""

    def __init__(self, port: int = 8000, host: str = "0.0.0.0"):
        """
        Initialize metrics server

        Args:
            port: Port to listen on (default: 8000)
            host: Host to bind to (default: 0.0.0.0)
        """
        self.port = port
        self.host = host
        self.server: Optional[socketserver.TCPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start metrics server in background thread"""
        if self.server is not None:
            logger.warning("Metrics server already running")
            return

        try:
            self.server = socketserver.TCPServer((self.host, self.port), MetricsHandler)
            self.server.allow_reuse_address = True

            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()

            logger.info("Metrics server started on %s:%d", self.host, self.port)
        except Exception as e:
            logger.error("Failed to start metrics server: %s", e, exc_info=True)
            raise

    def stop(self):
        """Stop metrics server"""
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            logger.info("Metrics server stopped")

    def is_running(self) -> bool:
        """Check if server is running"""
        return self.server is not None and self.thread is not None and self.thread.is_alive()


def start_metrics_server(port: int = 8000, host: str = "0.0.0.0") -> MetricsServer:
    """
    Start metrics server

    Args:
        port: Port to listen on (default: 8000)
        host: Host to bind to (default: 0.0.0.0)

    Returns:
        MetricsServer instance
    """
    server = MetricsServer(port=port, host=host)
    server.start()
    return server


if __name__ == "__main__":
    # Run standalone metrics server
    import signal
    import sys

    server = start_metrics_server()

    def signal_handler(sig, frame):
        logger.info("Shutting down metrics server...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Metrics server running. Press Ctrl+C to stop.")
    try:
        while True:
            import time

            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
