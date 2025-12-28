#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for exceptions module
"""

import pytest

from brs_kb.exceptions import (
    BRSKBError,
    ConfigurationError,
    ContextNotFoundError,
    DatabaseError,
    InvalidPayloadError,
    ModuleImportError,
    ValidationError,
)


class TestBRSKBError:
    """Test base exception class"""

    def test_base_exception(self):
        """Test base exception creation"""
        error = BRSKBError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_base_exception_with_details(self):
        """Test base exception with details"""
        error = BRSKBError("Test error")
        error.details = {"key": "value"}
        assert hasattr(error, "details")


class TestContextNotFoundError:
    """Test ContextNotFoundError"""

    def test_context_not_found_error(self):
        """Test context not found error"""
        error = ContextNotFoundError("html_invalid")
        assert "html_invalid" in str(error)
        assert isinstance(error, BRSKBError)
        assert error.context == "html_invalid"

    def test_context_not_found_error_with_available(self):
        """Test context not found error with available contexts"""
        error = ContextNotFoundError("test", available_contexts=["html_content", "js_string"])
        assert "test" in str(error)
        assert error.details["available"] == ["html_content", "js_string"]


class TestInvalidPayloadError:
    """Test InvalidPayloadError"""

    def test_invalid_payload_error(self):
        """Test invalid payload error"""
        error = InvalidPayloadError("<script>alert(1)</script>")
        assert "<script>" in str(error)
        assert isinstance(error, BRSKBError)
        assert error.details["payload"] == "<script>alert(1)</script>"

    def test_invalid_payload_error_with_reason(self):
        """Test invalid payload error with reason"""
        error = InvalidPayloadError("<script>", reason="Contains script tag")
        assert "<script>" in str(error)
        assert "Contains script tag" in str(error)
        assert error.details["reason"] == "Contains script tag"


class TestValidationError:
    """Test ValidationError"""

    def test_validation_error(self):
        """Test validation error"""
        error = ValidationError("field", "value", "Must be valid")
        assert "field" in str(error)
        assert "Must be valid" in str(error)
        assert isinstance(error, BRSKBError)

    def test_validation_error_attributes(self):
        """Test validation error attributes"""
        error = ValidationError("field", "value", "Must be valid")
        assert error.details["field"] == "field"
        assert error.details["value"] == "value"
        assert error.details["reason"] == "Must be valid"

    def test_validation_error_str_representation(self):
        """Test validation error string representation"""
        error = ValidationError("context", "invalid", "Must be lowercase")
        error_str = str(error)
        assert "context" in error_str
        assert "Must be lowercase" in error_str


class TestDatabaseError:
    """Test DatabaseError"""

    def test_database_error(self):
        """Test database error"""
        error = DatabaseError("connect", "Connection timeout")
        assert "connect" in str(error)
        assert "Connection timeout" in str(error)
        assert isinstance(error, BRSKBError)
        assert error.details["operation"] == "connect"

    def test_database_error_details(self):
        """Test database error details"""
        error = DatabaseError("insert", "Duplicate key")
        assert error.details["operation"] == "insert"
        assert error.details["reason"] == "Duplicate key"


class TestConfigurationError:
    """Test ConfigurationError"""

    def test_configuration_error(self):
        """Test configuration error"""
        error = ConfigurationError("API_KEY", "Missing required key")
        assert "API_KEY" in str(error)
        assert "Missing required key" in str(error)
        assert isinstance(error, BRSKBError)
        assert error.details["config_key"] == "API_KEY"

    def test_configuration_error_details(self):
        """Test configuration error details"""
        error = ConfigurationError("DATABASE_URL", "Invalid format")
        assert error.details["config_key"] == "DATABASE_URL"
        assert error.details["reason"] == "Invalid format"


class TestModuleImportError:
    """Test ModuleImportError"""

    def test_module_import_error(self):
        """Test module import error"""
        error = ModuleImportError("test_module", "No module named 'test_module'")
        assert "test_module" in str(error)
        assert "No module named" in str(error)
        assert isinstance(error, BRSKBError)
        assert error.details["module"] == "test_module"

    def test_module_import_error_details(self):
        """Test module import error details"""
        error = ModuleImportError("brs_kb.invalid", "ImportError")
        assert error.details["module"] == "brs_kb.invalid"
        assert error.details["reason"] == "ImportError"


class TestExceptionHierarchy:
    """Test exception hierarchy"""

    def test_all_exceptions_inherit_from_base(self):
        """Test that all exceptions inherit from BRSKBError"""
        exceptions = [
            (ContextNotFoundError, ("test_context",)),
            (InvalidPayloadError, ("<script>",)),
            (ValidationError, ("field", "value", "reason")),
            (DatabaseError, ("operation", "reason")),
            (ConfigurationError, ("key", "reason")),
            (ModuleImportError, ("module", "reason")),
        ]

        for exc_class, args in exceptions:
            error = exc_class(*args)
            assert isinstance(error, BRSKBError)
            assert isinstance(error, Exception)

    def test_exception_can_be_caught_by_base(self):
        """Test that specific exceptions can be caught by base"""
        try:
            raise ContextNotFoundError("test")
        except BRSKBError as e:
            assert isinstance(e, ContextNotFoundError)

    def test_exception_can_be_caught_by_exception(self):
        """Test that exceptions can be caught by Exception"""
        try:
            raise ValidationError("field", "value", "message")
        except Exception as e:
            assert isinstance(e, BRSKBError)
            assert isinstance(e, ValidationError)


class TestExceptionUsage:
    """Test exception usage patterns"""

    def test_raise_and_catch_specific(self):
        """Test raising and catching specific exception"""
        with pytest.raises(ContextNotFoundError) as exc_info:
            raise ContextNotFoundError("test_context")

        assert "test_context" in str(exc_info.value)

    def test_raise_and_catch_base(self):
        """Test raising and catching base exception"""
        with pytest.raises(BRSKBError):
            raise InvalidPayloadError("Invalid")

    def test_exception_in_try_except(self):
        """Test exception in try-except block"""

        def test_function():
            raise ValidationError("field", "value", "Invalid")

        try:
            test_function()
            raise AssertionError("Should have raised exception")
        except ValidationError as e:
            assert e.details["field"] == "field"
            assert e.details["value"] == "value"
            assert e.details["reason"] == "Invalid"
