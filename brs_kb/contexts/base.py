#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Base class for XSS vulnerability contexts
Provides common functionality and validation
"""

from typing import Any, Dict, List, Optional

from brs_kb.validation import (
    validate_context_details,
    validate_cvss_score,
    validate_severity,
    validate_tags,
)


class ContextBase:
    """Base class for XSS vulnerability contexts"""

    def __init__(self, details: Dict[str, Any]):
        """
        Initialize context with details

        Args:
            details: Context details dictionary

        Raises:
            ValidationError: If details are invalid
        """
        self._details = validate_context_details(details)
        self._validate_metadata()

    def _validate_metadata(self) -> None:
        """Validate context metadata"""
        if "severity" in self._details:
            self._details["severity"] = validate_severity(self._details["severity"])

        if "cvss_score" in self._details:
            self._details["cvss_score"] = validate_cvss_score(self._details["cvss_score"])

        if "tags" in self._details:
            self._details["tags"] = validate_tags(self._details["tags"])

    @property
    def title(self) -> str:
        """Get context title"""
        return self._details.get("title", "")

    @property
    def severity(self) -> str:
        """Get severity level"""
        return self._details.get("severity", "medium")

    @property
    def cvss_score(self) -> float:
        """Get CVSS score"""
        return self._details.get("cvss_score", 0.0)

    @property
    def cvss_vector(self) -> Optional[str]:
        """Get CVSS vector string"""
        return self._details.get("cvss_vector")

    @property
    def reliability(self) -> str:
        """Get reliability level"""
        return self._details.get("reliability", "tentative")

    @property
    def cwe(self) -> List[str]:
        """Get CWE identifiers"""
        return self._details.get("cwe", [])

    @property
    def owasp(self) -> List[str]:
        """Get OWASP Top 10 mappings"""
        return self._details.get("owasp", [])

    @property
    def tags(self) -> List[str]:
        """Get context tags"""
        return self._details.get("tags", [])

    @property
    def description(self) -> str:
        """Get vulnerability description"""
        return self._details.get("description", "")

    @property
    def attack_vector(self) -> str:
        """Get attack vector description"""
        return self._details.get("attack_vector", "")

    @property
    def remediation(self) -> str:
        """Get remediation guidance"""
        return self._details.get("remediation", "")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert context to dictionary

        Returns:
            Dictionary with all context details
        """
        return self._details.copy()

    def get_metadata(self) -> Dict[str, Any]:
        """
        Get metadata only (without large text fields)

        Returns:
            Dictionary with metadata fields
        """
        return {
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "reliability": self.reliability,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "tags": self.tags,
        }

    def has_tag(self, tag: str) -> bool:
        """
        Check if context has specific tag

        Args:
            tag: Tag to check

        Returns:
            True if tag exists
        """
        return tag.lower() in [t.lower() for t in self.tags]

    def is_severity(self, severity: str) -> bool:
        """
        Check if context has specific severity

        Args:
            severity: Severity level to check

        Returns:
            True if severity matches
        """
        return self.severity.lower() == severity.lower()

    def get_summary(self) -> Dict[str, Any]:
        """
        Get context summary

        Returns:
            Dictionary with summary information
        """
        return {
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "tags": self.tags,
            "description_length": len(self.description),
            "attack_vector_length": len(self.attack_vector),
            "remediation_length": len(self.remediation),
        }


def create_context_from_dict(details: Dict[str, Any]) -> ContextBase:
    """
    Create context instance from dictionary

    Args:
        details: Context details dictionary

    Returns:
        ContextBase instance

    Raises:
        ValidationError: If details are invalid
    """
    return ContextBase(details)
