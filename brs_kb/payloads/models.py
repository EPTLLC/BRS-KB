#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Payload database models.
Enterprise-grade data structures for XSS payload management.
Full Enum-based type system for maximum type safety.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class Severity(str, Enum):
    """
    CVSS-aligned severity levels.

    Based on CVSS v3.1 qualitative severity rating scale.
    """

    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"  # CVSS 7.0-8.9
    MEDIUM = "medium"  # CVSS 4.0-6.9
    LOW = "low"  # CVSS 0.1-3.9
    INFO = "info"  # CVSS 0.0 (informational)

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """
        Determine severity from CVSS score.

        Args:
            score: CVSS base score (0.0-10.0).

        Returns:
            Corresponding Severity level.
        """
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.INFO

    def __ge__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return not self.__gt__(other)

    def __lt__(self, other: "Severity") -> bool:
        return not self.__ge__(other)


class Reliability(str, Enum):
    """Payload execution reliability rating."""

    CERTAIN = "certain"  # 100% reliable, always executes
    HIGH = "high"  # >90% reliable
    MEDIUM = "medium"  # 50-90% reliable
    LOW = "low"  # <50% reliable
    EXPERIMENTAL = "experimental"  # Untested or theoretical


class Encoding(str, Enum):
    """Payload encoding type."""

    NONE = "none"
    URL = "url"
    HTML = "html"
    HTML_ENTITIES = "html-entities"
    HTML_DECIMAL = "html-decimal"
    HTML_HEX = "html-hex"
    HTML_PADDED = "html-padded"
    HTML_PADDED_HEX = "html-padded-hex"
    UNICODE = "unicode"
    UNICODE_PARTIAL = "unicode-partial"
    BASE64 = "base64"
    HEX = "hex"
    DOUBLE_URL = "double-url"
    MIXED = "mixed"
    OTHER = "other"  # For edge cases like application/xhtml+xml


class AttackSurface(str, Enum):
    """Attack surface categories."""

    CLIENT = "client"
    SERVER = "server"
    BRIDGE = "bridge"
    FEDERATION = "federation"
    PUSH = "push"
    WIDGET = "widget"
    INTEGRATION = "integration"
    WEB = "web"
    API = "api"


def _normalize_severity(value: Union[str, Severity]) -> Severity:
    """Convert string or Severity to Severity enum."""
    if isinstance(value, Severity):
        return value
    try:
        return Severity(value.lower())
    except ValueError:
        raise ValueError(
            f"Invalid severity '{value}'. Must be one of: {[s.value for s in Severity]}"
        )


def _normalize_reliability(value: Union[str, Reliability]) -> Reliability:
    """Convert string or Reliability to Reliability enum."""
    if isinstance(value, Reliability):
        return value
    try:
        return Reliability(value.lower())
    except ValueError:
        raise ValueError(
            f"Invalid reliability '{value}'. Must be one of: {[r.value for r in Reliability]}"
        )


def _normalize_encoding(value: Union[str, Encoding]) -> Encoding:
    """Convert string or Encoding to Encoding enum."""
    if isinstance(value, Encoding):
        return value
    try:
        return Encoding(value.lower())
    except ValueError:
        raise ValueError(
            f"Invalid encoding '{value}'. Must be one of: {[e.value for e in Encoding]}"
        )


def _normalize_attack_surface(
    value: Optional[Union[str, AttackSurface]],
) -> Optional[AttackSurface]:
    """Convert string or AttackSurface to AttackSurface enum."""
    if value is None:
        return None
    if isinstance(value, AttackSurface):
        return value
    try:
        return AttackSurface(value.lower())
    except ValueError:
        raise ValueError(
            f"Invalid attack_surface '{value}'. Must be one of: {[a.value for a in AttackSurface]}"
        )


@dataclass
class PayloadEntry:
    """
    Enhanced payload entry with comprehensive metadata.

    Represents a single XSS payload with all associated metadata
    for categorization, filtering, and security assessment.
    Uses Enum types for type safety and IDE autocomplete.

    Attributes:
        payload: The actual XSS payload string.
        contexts: List of applicable injection contexts.
        severity: CVSS-aligned severity level (Enum).
        cvss_score: CVSS 3.1 base score (0.0-10.0).
        description: Human-readable payload description.
        tags: Searchable tags for categorization.
        bypasses: List of WAFs/filters this payload bypasses.
        encoding: Encoding type used in payload (Enum).
        browser_support: List of supported browsers.
        waf_evasion: Whether payload is designed for WAF evasion.
        tested_on: Platforms/frameworks tested against.
        reliability: Execution reliability rating (Enum).
        last_updated: ISO 8601 timestamp of last update.
        attack_surface: Target attack surface category (Enum).
        spec_ref: Specification reference (e.g., MSC number).
        known_affected: List of known affected versions.
        profile: Payload profile/category identifier.

    Example:
        >>> entry = PayloadEntry(
        ...     payload="<script>alert(1)</script>",
        ...     contexts=["html_content"],
        ...     severity=Severity.HIGH,  # or "high"
        ...     cvss_score=7.5,
        ...     description="Basic script injection"
        ... )
    """

    # Required fields
    payload: str
    contexts: List[str]
    severity: Union[str, Severity]
    cvss_score: float
    description: str

    # Optional fields with defaults
    tags: List[str] = field(default_factory=list)
    bypasses: List[str] = field(default_factory=list)
    encoding: Union[str, Encoding] = Encoding.NONE
    browser_support: List[str] = field(default_factory=list)
    waf_evasion: bool = False
    tested_on: List[str] = field(default_factory=list)
    reliability: Union[str, Reliability] = Reliability.HIGH
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    # Extended fields for enterprise auditing
    attack_surface: Optional[Union[str, AttackSurface]] = None
    spec_ref: Optional[str] = None
    known_affected: Optional[List[str]] = None
    profile: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate and normalize fields after initialization."""
        # Validate CVSS score range
        if not 0.0 <= self.cvss_score <= 10.0:
            raise ValueError(f"cvss_score must be 0.0-10.0, got {self.cvss_score}")

        # Normalize Enum fields (accepts both str and Enum)
        self.severity = _normalize_severity(self.severity)
        self.reliability = _normalize_reliability(self.reliability)
        self.encoding = _normalize_encoding(self.encoding)
        self.attack_surface = _normalize_attack_surface(self.attack_surface)

        # Ensure contexts is a list
        if isinstance(self.contexts, str):
            self.contexts = [self.contexts]

        # Normalize context names to lowercase
        self.contexts = [c.lower() for c in self.contexts]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation.
        Enum values are converted to strings for JSON serialization.

        Returns:
            Dictionary with all payload metadata.
        """
        result = asdict(self)
        # Convert Enum to string values
        result["severity"] = self.severity.value
        result["reliability"] = self.reliability.value
        result["encoding"] = self.encoding.value
        if self.attack_surface:
            result["attack_surface"] = self.attack_surface.value
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PayloadEntry":
        """
        Create PayloadEntry from dictionary.
        Automatically converts string values to Enums.

        Args:
            data: Dictionary with payload metadata.

        Returns:
            New PayloadEntry instance.
        """
        return cls(**data)

    def matches_context(self, context: str) -> bool:
        """
        Check if payload applies to given context.

        Args:
            context: Context name to check.

        Returns:
            True if payload applies to context.
        """
        return context.lower() in self.contexts

    def matches_severity(self, min_severity: Union[str, Severity]) -> bool:
        """
        Check if payload meets minimum severity threshold.
        Uses Enum comparison operators.

        Args:
            min_severity: Minimum severity level.

        Returns:
            True if payload severity >= min_severity.
        """
        if isinstance(min_severity, str):
            min_severity = _normalize_severity(min_severity)
        return self.severity >= min_severity

    def has_tag(self, tag: str) -> bool:
        """
        Check if payload has specified tag.

        Args:
            tag: Tag to search for.

        Returns:
            True if tag is present.
        """
        return tag.lower() in [t.lower() for t in self.tags]

    def bypasses_waf(self, waf_name: str) -> bool:
        """
        Check if payload bypasses specified WAF.

        Args:
            waf_name: WAF name to check.

        Returns:
            True if payload bypasses the WAF.
        """
        return waf_name.lower() in [b.lower() for b in self.bypasses]

    def __repr__(self) -> str:
        """Concise string representation for debugging."""
        payload_short = self.payload[:40] + "..." if len(self.payload) > 40 else self.payload
        return (
            f"PayloadEntry("
            f"severity={self.severity.value!r}, "
            f"cvss={self.cvss_score}, "
            f"contexts={len(self.contexts)}, "
            f"payload={payload_short!r})"
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"[{self.severity.value.upper()}] {self.description}: {self.payload[:50]}..."


# Type aliases for clarity
PayloadDatabase = Dict[str, PayloadEntry]
PayloadList = List[PayloadEntry]
