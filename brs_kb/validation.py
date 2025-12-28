#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Input validation module for BRS-KB
Provides validation functions for CLI and API inputs
"""

import re
from typing import Any, Dict, List

from brs_kb.exceptions import ValidationError


def validate_context_name(context: str) -> str:
    """
    Validate context name

    Args:
        context: Context name to validate

    Returns:
        Normalized context name

    Raises:
        ValidationError: If context name is invalid
    """
    if not isinstance(context, str):
        raise ValidationError("context", context, "Must be a string")

    context = context.strip().lower()

    if not context:
        raise ValidationError("context", context, "Cannot be empty")

    # Context names should be alphanumeric with underscores
    if not re.match(r"^[a-z0-9_]+$", context):
        raise ValidationError(
            "context",
            context,
            "Must contain only lowercase letters, numbers, and underscores",
        )

    if len(context) > 100:
        raise ValidationError("context", context, "Must be 100 characters or less")

    return context


def validate_payload(payload: str, max_length: int = 10000) -> str:
    """
    Validate payload string

    Args:
        payload: Payload to validate
        max_length: Maximum payload length

    Returns:
        Validated payload

    Raises:
        ValidationError: If payload is invalid
    """
    if not isinstance(payload, str):
        raise ValidationError("payload", payload, "Must be a string")

    payload = payload.strip()

    if not payload:
        raise ValidationError("payload", payload, "Cannot be empty")

    if len(payload) > max_length:
        raise ValidationError("payload", payload, f"Must be {max_length} characters or less")

    return payload


def validate_severity(severity: str) -> str:
    """
    Validate severity level

    Args:
        severity: Severity level to validate

    Returns:
        Normalized severity level

    Raises:
        ValidationError: If severity is invalid
    """
    if not isinstance(severity, str):
        raise ValidationError("severity", severity, "Must be a string")

    severity = severity.strip().lower()

    valid_severities = ["low", "medium", "high", "critical"]
    if severity not in valid_severities:
        raise ValidationError(
            "severity", severity, f"Must be one of: {', '.join(valid_severities)}"
        )

    return severity


def validate_cvss_score(score: float) -> float:
    """
    Validate CVSS score

    Args:
        score: CVSS score to validate

    Returns:
        Validated CVSS score

    Raises:
        ValidationError: If CVSS score is invalid
    """
    if not isinstance(score, (int, float)):
        raise ValidationError("cvss_score", score, "Must be a number")

    if score < 0.0 or score > 10.0:
        raise ValidationError("cvss_score", score, "Must be between 0.0 and 10.0")

    return float(score)


def validate_tags(tags: List[str]) -> List[str]:
    """
    Validate tags list

    Args:
        tags: Tags list to validate

    Returns:
        Validated tags list

    Raises:
        ValidationError: If tags are invalid
    """
    if not isinstance(tags, list):
        raise ValidationError("tags", tags, "Must be a list")

    validated_tags = []
    for tag in tags:
        if not isinstance(tag, str):
            raise ValidationError("tag", tag, "Must be a string")

        tag = tag.strip().lower()
        if not tag:
            continue

        if len(tag) > 50:
            raise ValidationError("tag", tag, "Must be 50 characters or less")

        if not re.match(r"^[a-z0-9_-]+$", tag):
            raise ValidationError(
                "tag", tag, "Must contain only lowercase letters, numbers, hyphens, and underscores"
            )

        validated_tags.append(tag)

    return validated_tags


def validate_search_query(query: str, min_length: int = 1, max_length: int = 200) -> str:
    """
    Validate search query

    Args:
        query: Search query to validate
        min_length: Minimum query length
        max_length: Maximum query length

    Returns:
        Validated search query

    Raises:
        ValidationError: If query is invalid
    """
    if not isinstance(query, str):
        raise ValidationError("query", query, "Must be a string")

    query = query.strip()

    if len(query) < min_length:
        raise ValidationError("query", query, f"Must be at least {min_length} character(s)")

    if len(query) > max_length:
        raise ValidationError("query", query, f"Must be {max_length} characters or less")

    return query


def validate_limit(limit: int, min_value: int = 1, max_value: int = 1000) -> int:
    """
    Validate limit parameter

    Args:
        limit: Limit value to validate
        min_value: Minimum limit value
        max_value: Maximum limit value

    Returns:
        Validated limit

    Raises:
        ValidationError: If limit is invalid
    """
    if not isinstance(limit, int):
        raise ValidationError("limit", limit, "Must be an integer")

    if limit < min_value:
        raise ValidationError("limit", limit, f"Must be at least {min_value}")

    if limit > max_value:
        raise ValidationError("limit", limit, f"Must be {max_value} or less")

    return limit


def validate_context_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate context details dictionary

    Args:
        details: Context details to validate

    Returns:
        Validated context details

    Raises:
        ValidationError: If details are invalid
    """
    if not isinstance(details, dict):
        raise ValidationError("details", details, "Must be a dictionary")

    required_fields = ["title", "description", "attack_vector", "remediation"]
    for field in required_fields:
        if field not in details:
            raise ValidationError("details", details, f"Missing required field: {field}")

        if not isinstance(details[field], str) or not details[field].strip():
            raise ValidationError("details", details, f"Field '{field}' must be a non-empty string")

    # Validate optional fields if present
    if "severity" in details:
        details["severity"] = validate_severity(details["severity"])

    if "cvss_score" in details:
        details["cvss_score"] = validate_cvss_score(details["cvss_score"])

    if "tags" in details:
        details["tags"] = validate_tags(details["tags"])

    return details
