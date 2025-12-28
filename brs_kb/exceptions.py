#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Custom exceptions for BRS-KB
Provides specific exception types for better error handling
"""
from typing import Optional


class BRSKBError(Exception):
    """Base exception for BRS-KB"""

    def __init__(self, message: str, context: Optional[str] = None, details: Optional[dict] = None):
        """
        Initialize BRS-KB error

        Args:
            message: Error message
            context: Optional context name
            details: Optional additional details
        """
        super().__init__(message)
        self.message = message
        self.context = context
        self.details = details or {}


class ContextNotFoundError(BRSKBError):
    """Raised when a context is not found"""

    def __init__(self, context: str, available_contexts: Optional[list] = None):
        """
        Initialize context not found error

        Args:
            context: Requested context name
            available_contexts: List of available contexts
        """
        message = f"Context '{context}' not found"
        if available_contexts:
            message += f". Available contexts: {', '.join(available_contexts[:5])}"
        super().__init__(message, context=context, details={"available": available_contexts})


class InvalidPayloadError(BRSKBError):
    """Raised when payload is invalid"""

    def __init__(self, payload: str, reason: Optional[str] = None):
        """
        Initialize invalid payload error

        Args:
            payload: Invalid payload
            reason: Reason for invalidity
        """
        message = f"Invalid payload: {payload[:50]}..."
        if reason:
            message += f" Reason: {reason}"
        super().__init__(message, details={"payload": payload, "reason": reason})


class ValidationError(BRSKBError):
    """Raised when validation fails"""

    def __init__(self, field: str, value: any, reason: str):
        """
        Initialize validation error

        Args:
            field: Field name that failed validation
            value: Invalid value
            reason: Reason for validation failure
        """
        message = f"Validation failed for field '{field}': {reason}"
        super().__init__(message, details={"field": field, "value": str(value), "reason": reason})


class DatabaseError(BRSKBError):
    """Raised when database operation fails"""

    def __init__(self, operation: str, reason: str):
        """
        Initialize database error

        Args:
            operation: Failed operation
            reason: Reason for failure
        """
        message = f"Database operation '{operation}' failed: {reason}"
        super().__init__(message, details={"operation": operation, "reason": reason})


class ConfigurationError(BRSKBError):
    """Raised when configuration is invalid"""

    def __init__(self, config_key: str, reason: str):
        """
        Initialize configuration error

        Args:
            config_key: Configuration key
            reason: Reason for error
        """
        message = f"Configuration error for '{config_key}': {reason}"
        super().__init__(message, details={"config_key": config_key, "reason": reason})


class ModuleImportError(BRSKBError):
    """Raised when module import fails"""

    def __init__(self, module_name: str, reason: str):
        """
        Initialize import error

        Args:
            module_name: Module name that failed to import
            reason: Reason for failure
        """
        message = f"Failed to import module '{module_name}': {reason}"
        super().__init__(message, details={"module": module_name, "reason": reason})
