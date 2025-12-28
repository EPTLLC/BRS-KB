#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Payload Strategy Engine.
Generates scanning strategies based on target analysis.

This is the integration point with BRS-XSS.
KB dictates strategy. Scanner executes.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..payloads.models import PayloadEntry, Severity
from .context_matcher import ContextDetection, ContextMatcher
from .ranker import PayloadRanker, RankingStrategy
from .scoring import PayloadScorer


class ScanMode(str, Enum):
    """Scanning mode based on target analysis."""

    AGGRESSIVE = "aggressive"  # All payloads, high concurrency
    BALANCED = "balanced"  # Smart selection, medium concurrency
    STEALTH = "stealth"  # Minimal footprint, low concurrency
    TARGETED = "targeted"  # Specific context/surface only
    WAF_BYPASS = "waf_bypass"  # Focus on WAF evasion


@dataclass
class PayloadStrategy:
    """
    Strategy for a single payload test.

    Tells the scanner exactly how to use this payload.
    """

    payload_id: str
    payload: str
    priority: int
    context: str
    encoding_hint: str
    headers: Dict[str, str] = field(default_factory=dict)
    delay_ms: int = 0
    verify_method: str = "reflection"  # reflection, callback, dom
    expected_behavior: str = ""
    fallback_payloads: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "payload_id": self.payload_id,
            "payload": self.payload,
            "priority": self.priority,
            "context": self.context,
            "encoding_hint": self.encoding_hint,
            "headers": self.headers,
            "delay_ms": self.delay_ms,
            "verify_method": self.verify_method,
            "expected_behavior": self.expected_behavior,
            "fallback_payloads": self.fallback_payloads,
        }


@dataclass
class ScanStrategy:
    """
    Complete scanning strategy for a target.

    This is what BRS-KB provides to BRS-XSS.
    Not a payload list - a battle plan.
    """

    target_url: str
    mode: ScanMode
    detected_contexts: List[ContextDetection]
    payload_strategies: List[PayloadStrategy]

    # Configuration
    concurrency: int = 5
    timeout_ms: int = 5000
    retry_count: int = 2
    waf_detected: Optional[str] = None

    # Metadata
    total_payloads: int = 0
    estimated_time_seconds: int = 0
    confidence: float = 0.0
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "target_url": self.target_url,
            "mode": self.mode.value,
            "detected_contexts": [
                {
                    "context": c.context,
                    "type": c.context_type.value,
                    "confidence": c.confidence,
                }
                for c in self.detected_contexts
            ],
            "payload_strategies": [p.to_dict() for p in self.payload_strategies],
            "config": {
                "concurrency": self.concurrency,
                "timeout_ms": self.timeout_ms,
                "retry_count": self.retry_count,
                "waf_detected": self.waf_detected,
            },
            "meta": {
                "total_payloads": self.total_payloads,
                "estimated_time_seconds": self.estimated_time_seconds,
                "confidence": self.confidence,
                "reasoning": self.reasoning,
            },
        }


class StrategyEngine:
    """
    Generates scanning strategies from target analysis.

    This is the brain of the KB-Scanner integration.

    Flow:
    1. Analyze target (response, headers, WAF detection)
    2. Detect contexts
    3. Select appropriate payloads
    4. Order by priority
    5. Generate strategy with timing and encoding hints

    Usage:
        engine = StrategyEngine(payloads)
        strategy = engine.generate(
            url="https://target.com/search?q=test",
            response=response_html,
            waf="cloudflare"
        )
        # Now BRS-XSS knows exactly what to do
    """

    # Mode configurations
    MODE_CONFIG = {
        ScanMode.AGGRESSIVE: {
            "concurrency": 20,
            "payload_limit": None,
            "ranking": RankingStrategy.PRIORITY,
            "min_severity": None,
        },
        ScanMode.BALANCED: {
            "concurrency": 10,
            "payload_limit": 500,
            "ranking": RankingStrategy.PRIORITY,
            "min_severity": Severity.LOW,
        },
        ScanMode.STEALTH: {
            "concurrency": 2,
            "payload_limit": 50,
            "ranking": RankingStrategy.STEALTH,
            "min_severity": Severity.MEDIUM,
        },
        ScanMode.TARGETED: {
            "concurrency": 5,
            "payload_limit": 100,
            "ranking": RankingStrategy.FAST,
            "min_severity": None,
        },
        ScanMode.WAF_BYPASS: {
            "concurrency": 5,
            "payload_limit": 200,
            "ranking": RankingStrategy.WAF_EVASION,
            "min_severity": None,
        },
    }

    # Delay between requests based on WAF detection
    WAF_DELAYS = {
        "cloudflare": 500,
        "akamai": 300,
        "aws_waf": 200,
        "imperva": 400,
        "modsecurity": 100,
        None: 0,
    }

    def __init__(self, payloads: Dict[str, PayloadEntry]):
        """
        Initialize strategy engine.

        Args:
            payloads: The full payload database
        """
        self.payloads = payloads
        self.ranker = PayloadRanker(payloads)
        self.context_matcher = ContextMatcher()
        self.scorer = PayloadScorer()

    def generate(
        self,
        url: str,
        response: Optional[str] = None,
        injection_point: Optional[str] = None,
        mode: ScanMode = ScanMode.BALANCED,
        waf: Optional[str] = None,
        surface: Optional[str] = None,
        custom_contexts: Optional[List[str]] = None,
    ) -> ScanStrategy:
        """
        Generate a complete scanning strategy.

        Args:
            url: Target URL
            response: HTTP response body (for context detection)
            injection_point: The parameter or location being tested
            mode: Scanning mode
            waf: Detected WAF (if any)
            surface: Attack surface (client/server/etc)
            custom_contexts: Override context detection

        Returns:
            Complete ScanStrategy for BRS-XSS to execute
        """
        config = self.MODE_CONFIG[mode]
        reasoning_parts = []

        # Step 1: Detect contexts
        if custom_contexts:
            contexts = [
                ContextDetection(
                    context=c,
                    context_type=self._infer_context_type(c),
                    confidence=1.0,
                    position=0,
                    evidence="user_specified",
                    recommended_payloads=[],
                )
                for c in custom_contexts
            ]
            reasoning_parts.append(f"contexts=user_specified({len(contexts)})")
        elif response:
            contexts = self.context_matcher.detect(response, injection_point)
            reasoning_parts.append(f"contexts=auto_detected({len(contexts)})")
        else:
            contexts = [
                ContextDetection(
                    context="html_content",
                    context_type=self.context_matcher.PATTERNS["html_content"]["type"],
                    confidence=0.5,
                    position=0,
                    evidence="default",
                    recommended_payloads=["html", "script"],
                )
            ]
            reasoning_parts.append("contexts=default(html_content)")

        # Step 2: Get primary context for ranking
        primary_context = contexts[0].context if contexts else "html_content"
        reasoning_parts.append(f"primary={primary_context}")

        # Step 3: Rank payloads
        profile = config.get("profile")

        ranked = list(
            self.ranker.rank(
                context=primary_context,
                surface=surface,
                profile=profile,
                strategy=config["ranking"],
                limit=config["payload_limit"],
                min_severity=config["min_severity"],
                waf_only=(mode == ScanMode.WAF_BYPASS),
            )
        )

        reasoning_parts.append(f"payloads={len(ranked)}")

        # Step 4: Generate payload strategies
        delay = self.WAF_DELAYS.get(waf, 0)
        payload_strategies = []

        for rp in ranked:
            strategy = PayloadStrategy(
                payload_id=rp.payload_id,
                payload=rp.payload.payload,
                priority=rp.rank,
                context=primary_context,
                encoding_hint=rp.payload.encoding.value,
                delay_ms=delay,
                verify_method=self._get_verify_method(rp.payload),
                expected_behavior=rp.payload.description,
            )
            payload_strategies.append(strategy)

        # Step 5: Calculate estimates
        estimated_time = self._estimate_time(
            payload_count=len(ranked),
            concurrency=config["concurrency"],
            delay_ms=delay,
        )

        confidence = contexts[0].confidence if contexts else 0.5

        return ScanStrategy(
            target_url=url,
            mode=mode,
            detected_contexts=contexts,
            payload_strategies=payload_strategies,
            concurrency=config["concurrency"],
            timeout_ms=5000,
            retry_count=2,
            waf_detected=waf,
            total_payloads=len(ranked),
            estimated_time_seconds=estimated_time,
            confidence=confidence,
            reasoning=" | ".join(reasoning_parts),
        )

    def _infer_context_type(self, context: str):
        """Infer context type from context name."""
        from .context_matcher import ContextType

        if context.startswith("html") or context in ["svg"]:
            return ContextType.HTML
        elif context.startswith("js") or context == "javascript":
            return ContextType.JAVASCRIPT
        elif context.startswith("css"):
            return ContextType.CSS
        elif context.startswith("url"):
            return ContextType.URL
        elif context.startswith("json"):
            return ContextType.JSON
        elif context.startswith("xml"):
            return ContextType.XML
        elif context.startswith("template"):
            return ContextType.TEMPLATE
        elif context.startswith("graphql") or context.startswith("websocket"):
            return ContextType.API
        return ContextType.UNKNOWN

    def _get_verify_method(self, payload: PayloadEntry) -> str:
        """Determine best verification method for payload."""
        if "blind" in payload.tags or "callback" in payload.tags:
            return "callback"
        if "dom" in payload.tags or "dom_xss" in payload.contexts:
            return "dom"
        return "reflection"

    def _estimate_time(
        self,
        payload_count: int,
        concurrency: int,
        delay_ms: int,
    ) -> int:
        """Estimate scan time in seconds."""
        base_time_per_request = 0.5  # 500ms average
        requests_per_batch = concurrency
        batches = (payload_count + requests_per_batch - 1) // requests_per_batch
        delay_time = (delay_ms / 1000) * payload_count

        return int(batches * base_time_per_request + delay_time)

    def recommend_mode(
        self,
        waf_detected: bool = False,
        stealth_required: bool = False,
        time_limit_seconds: Optional[int] = None,
    ) -> ScanMode:
        """
        Recommend best scanning mode based on conditions.

        Args:
            waf_detected: Is a WAF present?
            stealth_required: Need to avoid detection?
            time_limit_seconds: Maximum time available

        Returns:
            Recommended ScanMode
        """
        if stealth_required:
            return ScanMode.STEALTH

        if waf_detected:
            return ScanMode.WAF_BYPASS

        if time_limit_seconds and time_limit_seconds < 60:
            return ScanMode.TARGETED

        return ScanMode.BALANCED
