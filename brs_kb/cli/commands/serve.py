#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 22:53:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

CLI command: serve - Start API server for Web UI integration
"""

import signal
import sys
from typing import Any

from .base import BaseCommand


class ServeCommand(BaseCommand):
    """Command to start API server"""

    def add_parser(self, subparsers: Any) -> Any:
        """Add command parser to subparsers"""
        parser = subparsers.add_parser(
            "serve",
            help="Start REST API server for Web UI integration",
        )
        parser.add_argument(
            "--port",
            type=int,
            default=8080,
            help="Port to listen on (default: 8080)",
        )
        parser.add_argument(
            "--host",
            type=str,
            default="0.0.0.0",
            help="Host to bind to (default: 0.0.0.0)",
        )
        parser.add_argument(
            "--metrics",
            action="store_true",
            help="Enable Prometheus metrics server",
        )
        parser.add_argument(
            "--metrics-port",
            type=int,
            default=8000,
            help="Metrics server port (default: 8000)",
        )
        return parser

    def execute(self, args) -> int:
        """Execute serve command"""
        from brs_kb.api_server import start_api_server
        from brs_kb.logger import get_logger

        get_logger("brs_kb.cli.serve")

        port = getattr(args, "port", 8080)
        host = getattr(args, "host", "0.0.0.0")
        metrics = getattr(args, "metrics", False)
        metrics_port = getattr(args, "metrics_port", 8000)

        print(f"Starting BRS-KB API server on http://{host}:{port}")
        print("=" * 60)

        # Start API server
        api_server = start_api_server(port=port, host=host)

        # Start metrics server if requested
        metrics_server = None
        if metrics:
            from brs_kb.metrics_server import start_metrics_server

            metrics_server = start_metrics_server(port=metrics_port, host=host)
            print(f"Metrics server started on http://{host}:{metrics_port}/metrics")

        print()
        print("API Endpoints:")
        print(f"  GET  http://{host}:{port}/api/info           - System information")
        print(f"  GET  http://{host}:{port}/api/contexts       - List all contexts")
        print(f"  GET  http://{host}:{port}/api/contexts/<id>  - Get context details")
        print(f"  GET  http://{host}:{port}/api/payloads       - List payloads")
        print(f"  GET  http://{host}:{port}/api/payloads/search?q=<query> - Search payloads")
        print(f"  POST http://{host}:{port}/api/analyze        - Analyze payload")
        print(f"  GET  http://{host}:{port}/api/defenses?context=<ctx> - Get defenses")
        print(f"  GET  http://{host}:{port}/api/stats          - Get statistics")
        print(f"  GET  http://{host}:{port}/api/health         - Health check")
        print()
        print("Press Ctrl+C to stop the server...")
        print()

        # Set up signal handlers
        def signal_handler(sig, frame):
            print("\nShutting down...")
            api_server.stop()
            if metrics_server:
                metrics_server.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Keep running
        try:
            while True:
                import time

                time.sleep(1)
        except KeyboardInterrupt:
            signal_handler(None, None)

        return 0
