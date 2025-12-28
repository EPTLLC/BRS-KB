#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 22:53:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

REST API server for BRS-KB Web UI integration
Provides JSON API endpoints for all BRS-KB functionality
"""

import http.server
import json
import socketserver
import threading
import urllib.parse
from typing import Any, Dict, Optional

from brs_kb.logger import get_logger


logger = get_logger("brs_kb.api_server")

# CORS headers for Web UI integration
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
}


class APIHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for REST API endpoints"""

    def _send_json_response(self, data: Any, status: int = 200):
        """Send JSON response with CORS headers"""
        self.send_response(status)
        self.send_header("Content-type", "application/json; charset=utf-8")
        for header, value in CORS_HEADERS.items():
            self.send_header(header, value)
        self.end_headers()

        response = json.dumps(data, ensure_ascii=False, indent=2)
        self.wfile.write(response.encode("utf-8"))

    def _send_error_response(self, message: str, status: int = 400):
        """Send error response"""
        self._send_json_response({"error": message, "status": status}, status)

    def _parse_query_params(self) -> Dict[str, str]:
        """Parse query parameters from URL"""
        parsed = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def _get_path(self) -> str:
        """Get clean path without query string"""
        return urllib.parse.urlparse(self.path).path

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        for header, value in CORS_HEADERS.items():
            self.send_header(header, value)
        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        path = self._get_path()
        params = self._parse_query_params()

        try:
            # Route requests to appropriate handlers
            if path == "/api/info":
                self._handle_info()
            elif path == "/api/contexts":
                self._handle_list_contexts()
            elif path.startswith("/api/contexts/"):
                context_id = path.replace("/api/contexts/", "")
                self._handle_get_context(context_id)
            elif path == "/api/payloads":
                self._handle_list_payloads(params)
            elif path == "/api/payloads/search":
                self._handle_search_payloads(params)
            elif path == "/api/analyze":
                self._handle_analyze_payload(params)
            elif path == "/api/defenses":
                self._handle_get_defenses(params)
            elif path == "/api/stats":
                self._handle_get_stats()
            elif path == "/api/health":
                self._handle_health()
            elif path == "/api/languages":
                self._handle_languages()
            else:
                self._send_error_response("Not Found", 404)
        except Exception as e:
            logger.error("API error: %s", e, exc_info=True)
            self._send_error_response(f"Internal Server Error: {e!s}", 500)

    def do_POST(self):
        """Handle POST requests"""
        path = self._get_path()

        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            data = json.loads(body) if body else {}

            if path == "/api/analyze":
                self._handle_analyze_payload_post(data)
            elif path == "/api/test-payload":
                self._handle_test_payload(data)
            elif path == "/api/language":
                self._handle_set_language(data)
            else:
                self._send_error_response("Not Found", 404)
        except json.JSONDecodeError:
            self._send_error_response("Invalid JSON", 400)
        except Exception as e:
            logger.error("API error: %s", e, exc_info=True)
            self._send_error_response(f"Internal Server Error: {e!s}", 500)

    def _handle_info(self):
        """Handle /api/info endpoint"""
        from brs_kb import get_database_info, get_kb_info
        from brs_kb.reverse_map import get_reverse_map_info

        kb_info = get_kb_info()
        db_info = get_database_info()
        rm_info = get_reverse_map_info()

        response = {
            "version": kb_info["version"],
            "build": kb_info["build"],
            "revision": kb_info["revision"],
            "total_contexts": kb_info["total_contexts"],
            "total_payloads": db_info.get("total_payloads", 0),
            "reverse_map_patterns": rm_info.get("total_patterns", 0),
            "supported_languages": ["en", "ru", "zh", "es"],
        }
        self._send_json_response(response)

    def _handle_list_contexts(self):
        """Handle /api/contexts endpoint"""
        from brs_kb import get_vulnerability_details, list_contexts

        contexts = []
        for context_id in list_contexts():
            try:
                details = get_vulnerability_details(context_id)
                contexts.append(
                    {
                        "id": context_id,
                        "title": details.get("title", ""),
                        "severity": details.get("severity", "medium"),
                        "cvss_score": details.get("cvss_score", 0.0),
                        "cvss_vector": details.get("cvss_vector", ""),
                        "cwe": details.get("cwe", []),
                        "owasp": details.get("owasp", []),
                        "tags": details.get("tags", []),
                        "description": details.get("description", "")[:300] + "...",
                    }
                )
            except Exception as e:
                logger.warning("Failed to get context %s: %s", context_id, e)

        self._send_json_response(
            {
                "contexts": contexts,
                "total": len(contexts),
            }
        )

    def _handle_get_context(self, context_id: str):
        """Handle /api/contexts/<id> endpoint"""
        from brs_kb import get_vulnerability_details
        from brs_kb.exceptions import ContextNotFoundError

        try:
            details = get_vulnerability_details(context_id)
            response = {
                "id": context_id,
                "title": details.get("title", ""),
                "description": details.get("description", ""),
                "attack_vector": details.get("attack_vector", ""),
                "remediation": details.get("remediation", ""),
                "severity": details.get("severity", "medium"),
                "cvss_score": details.get("cvss_score", 0.0),
                "cvss_vector": details.get("cvss_vector", ""),
                "reliability": details.get("reliability", ""),
                "cwe": details.get("cwe", []),
                "owasp": details.get("owasp", []),
                "tags": details.get("tags", []),
            }
            self._send_json_response(response)
        except ContextNotFoundError:
            self._send_error_response(f"Context not found: {context_id}", 404)

    def _handle_list_payloads(self, params: Dict[str, str]):
        """Handle /api/payloads endpoint"""
        from brs_kb.payloads import (
            FULL_PAYLOAD_DATABASE,
            get_payloads_by_context,
            get_payloads_by_severity,
            get_waf_bypass_payloads,
        )

        context = params.get("context")
        severity = params.get("severity")
        waf_bypass = params.get("waf_bypass", "").lower() == "true"
        limit = int(params.get("limit", 50))
        offset = int(params.get("offset", 0))

        if waf_bypass:
            payloads = get_waf_bypass_payloads()
        elif context:
            payloads = get_payloads_by_context(context)
        elif severity:
            payloads = get_payloads_by_severity(severity)
        else:
            payloads = list(FULL_PAYLOAD_DATABASE.values())

        # Convert to dict format
        payload_list = []
        for p in payloads[offset : offset + limit]:
            payload_list.append(
                {
                    "payload": p.payload,
                    "contexts": p.contexts,
                    "severity": p.severity,
                    "cvss_score": p.cvss_score,
                    "description": p.description,
                    "tags": p.tags,
                    "waf_evasion": p.waf_evasion,
                    "browser_support": p.browser_support,
                    "reliability": p.reliability,
                }
            )

        self._send_json_response(
            {
                "payloads": payload_list,
                "total": len(payloads),
                "offset": offset,
                "limit": limit,
            }
        )

    def _handle_search_payloads(self, params: Dict[str, str]):
        """Handle /api/payloads/search endpoint"""
        from brs_kb.payloads import search_payloads

        query = params.get("q", "")
        limit = int(params.get("limit", 20))

        if not query:
            self._send_error_response("Query parameter 'q' is required", 400)
            return

        results = search_payloads(query)[:limit]

        payload_list = []
        for payload, score in results:
            payload_list.append(
                {
                    "payload": payload.payload,
                    "contexts": payload.contexts,
                    "severity": payload.severity,
                    "cvss_score": payload.cvss_score,
                    "description": payload.description,
                    "tags": payload.tags,
                    "relevance_score": score,
                }
            )

        self._send_json_response(
            {
                "results": payload_list,
                "query": query,
                "total": len(payload_list),
            }
        )

    def _handle_analyze_payload(self, params: Dict[str, str]):
        """Handle GET /api/analyze endpoint"""
        from brs_kb.reverse_map import find_contexts_for_payload

        payload = params.get("payload", "")
        if not payload:
            self._send_error_response("Query parameter 'payload' is required", 400)
            return

        result = find_contexts_for_payload(payload)
        self._send_json_response(result)

    def _handle_analyze_payload_post(self, data: Dict[str, Any]):
        """Handle POST /api/analyze endpoint"""
        from brs_kb.reverse_map import find_contexts_for_payload, predict_contexts_ml_ready

        payload = data.get("payload", "")
        ml_features = data.get("ml_features", False)

        if not payload:
            self._send_error_response("Field 'payload' is required", 400)
            return

        if ml_features:
            result = predict_contexts_ml_ready(payload)
        else:
            result = find_contexts_for_payload(payload)

        self._send_json_response(result)

    def _handle_test_payload(self, data: Dict[str, Any]):
        """Handle POST /api/test-payload endpoint"""
        from brs_kb.payloads import test_payload_effectiveness

        payload_id = data.get("payload_id", "")
        context = data.get("context", "")

        if not payload_id or not context:
            self._send_error_response("Fields 'payload_id' and 'context' are required", 400)
            return

        result = test_payload_effectiveness(payload_id, context)
        self._send_json_response(result)

    def _handle_get_defenses(self, params: Dict[str, str]):
        """Handle /api/defenses endpoint"""
        from brs_kb.reverse_map import get_defense_effectiveness, get_recommended_defenses

        context = params.get("context")
        if not context:
            self._send_error_response("Query parameter 'context' is required", 400)
            return

        defenses = get_recommended_defenses(context)

        defense_list = []
        for defense in defenses:
            effectiveness = get_defense_effectiveness(defense.get("defense", ""))
            defense_list.append(
                {
                    **defense,
                    "effectiveness": effectiveness,
                }
            )

        self._send_json_response(
            {
                "context": context,
                "defenses": defense_list,
            }
        )

    def _handle_get_stats(self):
        """Handle /api/stats endpoint"""
        from brs_kb import get_database_info, list_contexts
        from brs_kb.payloads import FULL_PAYLOAD_DATABASE

        contexts = list_contexts()
        db_info = get_database_info()

        # Calculate severity distribution
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for payload in FULL_PAYLOAD_DATABASE.values():
            severity = payload.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Calculate context coverage
        context_counts = {}
        for payload in FULL_PAYLOAD_DATABASE.values():
            for ctx in payload.contexts:
                context_counts[ctx] = context_counts.get(ctx, 0) + 1

        self._send_json_response(
            {
                "total_contexts": len(contexts),
                "total_payloads": db_info.get("total_payloads", 0),
                "severity_distribution": severity_counts,
                "context_coverage": context_counts,
                "waf_bypass_count": len(
                    [p for p in FULL_PAYLOAD_DATABASE.values() if p.waf_evasion]
                ),
            }
        )

    def _handle_health(self):
        """Handle /api/health endpoint"""
        self._send_json_response({"status": "healthy", "service": "brs-kb-api"})

    def _handle_languages(self):
        """Handle /api/languages endpoint"""
        from brs_kb import get_current_language, get_supported_languages

        self._send_json_response(
            {
                "current": get_current_language(),
                "supported": get_supported_languages(),
            }
        )

    def _handle_set_language(self, data: Dict[str, Any]):
        """Handle POST /api/language endpoint"""
        from brs_kb import get_current_language, set_language

        language = data.get("language", "")
        if not language:
            self._send_error_response("Field 'language' is required", 400)
            return

        success = set_language(language)
        if success:
            self._send_json_response(
                {
                    "success": True,
                    "language": get_current_language(),
                }
            )
        else:
            self._send_error_response(f"Unsupported language: {language}", 400)

    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.debug("API %s", format % args)


class APIServer:
    """REST API server for BRS-KB"""

    def __init__(self, port: int = 8080, host: str = "0.0.0.0"):
        """
        Initialize API server

        Args:
            port: Port to listen on (default: 8080)
            host: Host to bind to (default: 0.0.0.0)
        """
        self.port = port
        self.host = host
        self.server: Optional[socketserver.TCPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start API server in background thread"""
        if self.server is not None:
            logger.warning("API server already running")
            return

        try:
            self.server = socketserver.TCPServer((self.host, self.port), APIHandler)
            self.server.allow_reuse_address = True

            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()

            logger.info("API server started on http://%s:%d", self.host, self.port)
        except Exception as e:
            logger.error("Failed to start API server: %s", e, exc_info=True)
            raise

    def stop(self):
        """Stop API server"""
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            logger.info("API server stopped")

    def is_running(self) -> bool:
        """Check if server is running"""
        return self.server is not None and self.thread is not None and self.thread.is_alive()


def start_api_server(port: int = 8080, host: str = "0.0.0.0") -> APIServer:
    """
    Start API server

    Args:
        port: Port to listen on (default: 8080)
        host: Host to bind to (default: 0.0.0.0)

    Returns:
        APIServer instance
    """
    server = APIServer(port=port, host=host)
    server.start()
    return server


if __name__ == "__main__":
    import signal
    import sys

    server = start_api_server()

    def signal_handler(sig, frame):
        logger.info("Shutting down API server...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("API server running on http://0.0.0.0:8080. Press Ctrl+C to stop.")
    print("API server running on http://0.0.0.0:8080")
    print("Endpoints:")
    print("  GET  /api/info           - System information")
    print("  GET  /api/contexts       - List all contexts")
    print("  GET  /api/contexts/<id>  - Get context details")
    print("  GET  /api/payloads       - List payloads")
    print("  GET  /api/payloads/search?q=<query> - Search payloads")
    print("  GET  /api/analyze?payload=<payload> - Analyze payload")
    print("  POST /api/analyze        - Analyze payload (JSON body)")
    print("  POST /api/test-payload   - Test payload effectiveness")
    print("  GET  /api/defenses?context=<context> - Get defenses")
    print("  GET  /api/stats          - Get statistics")
    print("  GET  /api/health         - Health check")
    print("  GET  /api/languages      - Get supported languages")
    print("  POST /api/language       - Set language")

    try:
        while True:
            import time

            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
