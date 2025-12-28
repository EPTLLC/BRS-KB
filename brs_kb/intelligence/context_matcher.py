#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Context Matcher.
Detects injection context from response analysis.

This is what makes BRS-KB context-aware. Not guessing - analyzing.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class ContextType(str, Enum):
    """High-level context categories."""

    HTML = "html"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URL = "url"
    JSON = "json"
    XML = "xml"
    TEMPLATE = "template"
    API = "api"
    UNKNOWN = "unknown"


@dataclass
class ContextDetection:
    """
    Detected injection context.

    Attributes:
        context: Specific context name (e.g., "html_attribute")
        context_type: High-level category
        confidence: Detection confidence (0.0-1.0)
        position: Position in response where detected
        evidence: What triggered the detection
        recommended_payloads: Suggested payload tags
    """

    context: str
    context_type: ContextType
    confidence: float
    position: int
    evidence: str
    recommended_payloads: List[str]

    def __repr__(self) -> str:
        return f"Context({self.context}, conf={self.confidence:.2f})"


class ContextMatcher:
    """
    Matches injection points to contexts.

    Given a response and injection point, determines the most likely
    context for successful XSS execution.

    This is the bridge between detection and exploitation.

    Usage:
        matcher = ContextMatcher()
        contexts = matcher.detect(response, injection_marker)
        # Returns sorted list of ContextDetection
    """

    # Context detection patterns
    PATTERNS: Dict[str, Dict] = {
        # HTML contexts
        "html_content": {
            "type": ContextType.HTML,
            "patterns": [
                r"<[a-z]+[^>]*>[^<]*MARKER[^<]*<",
                r">MARKER<",
            ],
            "confidence": 0.9,
            "payloads": ["html", "script", "event"],
        },
        "html_attribute": {
            "type": ContextType.HTML,
            "patterns": [
                r'<[a-z]+[^>]*\s[a-z-]+=["\'][^"\']*MARKER[^"\']*["\']',
                r"<[a-z]+[^>]*\s[a-z-]+=MARKER",
            ],
            "confidence": 0.95,
            "payloads": ["attribute", "event", "javascript"],
        },
        "html_comment": {
            "type": ContextType.HTML,
            "patterns": [
                r"<!--[^>]*MARKER[^>]*-->",
            ],
            "confidence": 0.85,
            "payloads": ["comment_breakout"],
        },
        "html_tag_name": {
            "type": ContextType.HTML,
            "patterns": [
                r"<MARKER[^>]*>",
                r"</MARKER>",
            ],
            "confidence": 0.7,
            "payloads": ["tag_injection"],
        },
        # JavaScript contexts
        "js_string": {
            "type": ContextType.JAVASCRIPT,
            "patterns": [
                r'["\'][^"\']*MARKER[^"\']*["\']',
                r"`[^`]*MARKER[^`]*`",
            ],
            "confidence": 0.9,
            "payloads": ["string_breakout", "template_literal"],
        },
        "javascript": {
            "type": ContextType.JAVASCRIPT,
            "patterns": [
                r"<script[^>]*>[^<]*MARKER[^<]*</script>",
                r"javascript:[^\"']*MARKER",
            ],
            "confidence": 0.95,
            "payloads": ["javascript", "script_injection"],
        },
        "js_object": {
            "type": ContextType.JAVASCRIPT,
            "patterns": [
                r"\{[^}]*MARKER[^}]*\}",
                r":\s*MARKER\s*[,}]",
            ],
            "confidence": 0.8,
            "payloads": ["object_injection", "prototype"],
        },
        # URL contexts
        "url": {
            "type": ContextType.URL,
            "patterns": [
                r'href=["\'][^"\']*MARKER[^"\']*["\']',
                r'src=["\'][^"\']*MARKER[^"\']*["\']',
                r'action=["\'][^"\']*MARKER[^"\']*["\']',
            ],
            "confidence": 0.9,
            "payloads": ["url", "javascript", "data_uri"],
        },
        "url_injection": {
            "type": ContextType.URL,
            "patterns": [
                r"\?[^#]*MARKER",
                r"#.*MARKER",
            ],
            "confidence": 0.75,
            "payloads": ["url_param", "fragment"],
        },
        # CSS contexts
        "css": {
            "type": ContextType.CSS,
            "patterns": [
                r"<style[^>]*>[^<]*MARKER[^<]*</style>",
                r'style=["\'][^"\']*MARKER[^"\']*["\']',
            ],
            "confidence": 0.85,
            "payloads": ["css", "expression"],
        },
        # JSON contexts
        "json_context": {
            "type": ContextType.JSON,
            "patterns": [
                r'"[^"]*":\s*"[^"]*MARKER[^"]*"',
                r'"[^"]*":\s*MARKER\s*[,}]',
            ],
            "confidence": 0.9,
            "payloads": ["json", "json_breakout"],
        },
        # Template contexts
        "template_context": {
            "type": ContextType.TEMPLATE,
            "patterns": [
                r"\{\{[^}]*MARKER[^}]*\}\}",  # Angular/Vue/Handlebars
                r"\$\{[^}]*MARKER[^}]*\}",  # Template literals
                r"<%[^%]*MARKER[^%]*%>",  # EJS/ERB
            ],
            "confidence": 0.95,
            "payloads": ["template", "ssti"],
        },
        # API contexts
        "graphql_query": {
            "type": ContextType.API,
            "patterns": [
                r'"query"\s*:\s*"[^"]*MARKER',
                r"query\s*\{[^}]*MARKER",
            ],
            "confidence": 0.9,
            "payloads": ["graphql"],
        },
        "websocket_message": {
            "type": ContextType.API,
            "patterns": [
                r'"type"\s*:\s*"[^"]*MARKER',
            ],
            "confidence": 0.7,
            "payloads": ["websocket"],
        },
        # SVG/XML contexts
        "svg": {
            "type": ContextType.XML,
            "patterns": [
                r"<svg[^>]*>[^<]*MARKER",
                r"<[a-z]+:svg[^>]*>",
            ],
            "confidence": 0.9,
            "payloads": ["svg", "xml"],
        },
        "xml_context": {
            "type": ContextType.XML,
            "patterns": [
                r"<\?xml[^>]*\?>.*MARKER",
            ],
            "confidence": 0.85,
            "payloads": ["xml", "xxe"],
        },
    }

    def __init__(self, marker: str = "MARKER"):
        """
        Initialize context matcher.

        Args:
            marker: The injection marker to look for in responses
        """
        self.marker = marker
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for context, config in self.PATTERNS.items():
            self._compiled_patterns[context] = [
                re.compile(p.replace("MARKER", re.escape(self.marker)), re.IGNORECASE | re.DOTALL)
                for p in config["patterns"]
            ]

    def detect(
        self,
        response: str,
        injection_value: Optional[str] = None,
    ) -> List[ContextDetection]:
        """
        Detect injection context from response.

        Args:
            response: The HTTP response body
            injection_value: Optional specific value to look for (instead of marker)

        Returns:
            List of ContextDetection sorted by confidence (highest first)
        """
        if injection_value:
            # Replace actual injection value with marker for detection
            response = response.replace(injection_value, self.marker)

        detections: List[ContextDetection] = []

        for context_name, config in self.PATTERNS.items():
            patterns = self._compiled_patterns[context_name]

            for pattern in patterns:
                match = pattern.search(response)
                if match:
                    detections.append(
                        ContextDetection(
                            context=context_name,
                            context_type=config["type"],
                            confidence=config["confidence"],
                            position=match.start(),
                            evidence=match.group(0)[:100],  # First 100 chars
                            recommended_payloads=config["payloads"],
                        )
                    )
                    break  # One match per context is enough

        # Sort by confidence
        detections.sort(key=lambda x: x.confidence, reverse=True)

        return detections

    def detect_all_positions(
        self,
        response: str,
        injection_value: str,
    ) -> Dict[int, ContextDetection]:
        """
        Detect context for each occurrence of injection value.

        Args:
            response: The HTTP response body
            injection_value: The value to find

        Returns:
            Dictionary mapping position -> ContextDetection
        """
        positions = {}
        start = 0

        while True:
            pos = response.find(injection_value, start)
            if pos == -1:
                break

            # Analyze context around this position
            window_start = max(0, pos - 100)
            window_end = min(len(response), pos + len(injection_value) + 100)
            window = response[window_start:window_end]

            # Replace injection value with marker in window
            window_with_marker = window.replace(injection_value, self.marker, 1)

            detections = self.detect(window_with_marker)
            if detections:
                positions[pos] = detections[0]  # Highest confidence

            start = pos + 1

        return positions

    def get_recommended_contexts(self, response_snippet: str) -> List[str]:
        """
        Quick analysis of response snippet for context hints.

        Returns list of context names that might apply.
        """
        contexts = []

        # Simple heuristics
        if "<script" in response_snippet.lower():
            contexts.append("javascript")
        if "{{" in response_snippet or "${" in response_snippet:
            contexts.append("template_context")
        if "<svg" in response_snippet.lower():
            contexts.append("svg")
        if "application/json" in response_snippet.lower() or response_snippet.strip().startswith(
            "{"
        ):
            contexts.append("json_context")
        if "<style" in response_snippet.lower() or "style=" in response_snippet.lower():
            contexts.append("css")

        return contexts if contexts else ["html_content"]  # Default
