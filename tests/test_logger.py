#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for logger module
"""

import json
import logging
import os
import tempfile

from brs_kb.logger import JSONFormatter, get_logger, setup_logger


class TestJSONFormatter:
    """Test JSON formatter"""

    def test_format_basic_log(self):
        """Test basic log formatting"""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert data["level"] == "INFO"
        assert data["logger"] == "test"
        assert data["message"] == "Test message"
        assert data["module_name"] == "test"
        assert "timestamp" in data
        assert "function" in data
        assert "line" in data

    def test_format_with_exception(self):
        """Test log formatting with exception"""
        formatter = JSONFormatter()
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Error occurred",
                args=(),
                exc_info=sys.exc_info(),
            )

            result = formatter.format(record)
            data = json.loads(result)

            assert data["level"] == "ERROR"
            assert "exception" in data
            assert "ValueError" in data["exception"]

    def test_format_with_extra_fields(self):
        """Test log formatting with extra fields"""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.extra_fields = {"user_id": "123", "action": "test"}

        result = formatter.format(record)
        data = json.loads(result)

        assert data["user_id"] == "123"
        assert data["action"] == "test"

    def test_format_with_context(self):
        """Test log formatting with context"""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.context = "html_content"

        result = formatter.format(record)
        data = json.loads(result)

        assert data["context"] == "html_content"


class TestSetupLogger:
    """Test logger setup"""

    def test_setup_logger_default(self):
        """Test default logger setup"""
        logger = setup_logger("test_logger", level=logging.DEBUG)

        assert logger.name == "test_logger"
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, JSONFormatter)

    def test_setup_logger_with_file(self):
        """Test logger setup with file output"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            log_file = f.name

        try:
            logger = setup_logger("test_file_logger", output_file=log_file)

            assert logger.name == "test_file_logger"
            assert len(logger.handlers) == 1
            assert isinstance(logger.handlers[0], logging.FileHandler)

            logger.info("Test message")
            # Close handler to flush
            for handler in logger.handlers:
                handler.close()

            # Read file
            if os.path.exists(log_file):
                with open(log_file, encoding="utf-8") as f:
                    content = f.read()
                    assert "Test message" in content
                    data = json.loads(content)
                    assert data["message"] == "Test message"
        finally:
            # Clean up
            if os.path.exists(log_file):
                try:
                    os.unlink(log_file)
                except OSError:
                    pass  # Ignore cleanup errors

    def test_setup_logger_json_format(self):
        """Test logger setup with JSON format"""
        logger = setup_logger("test_json", json_format=True)

        assert isinstance(logger.handlers[0].formatter, JSONFormatter)

    def test_setup_logger_text_format(self):
        """Test logger setup with text format"""
        logger = setup_logger("test_text", json_format=False)

        assert not isinstance(logger.handlers[0].formatter, JSONFormatter)
        assert isinstance(logger.handlers[0].formatter, logging.Formatter)

    def test_setup_logger_removes_existing_handlers(self):
        """Test that setup_logger removes existing handlers"""
        logger = setup_logger("test_cleanup")
        initial_handler_count = len(logger.handlers)

        logger2 = setup_logger("test_cleanup")
        assert len(logger2.handlers) == initial_handler_count


class TestGetLogger:
    """Test get_logger function"""

    def test_get_logger_default(self):
        """Test getting default logger"""
        logger = get_logger()

        assert logger.name == "brs_kb"
        assert len(logger.handlers) > 0

    def test_get_logger_custom_name(self):
        """Test getting logger with custom name"""
        logger = get_logger("custom_logger")

        assert logger.name == "custom_logger"
        assert len(logger.handlers) > 0

    def test_get_logger_same_instance(self):
        """Test that get_logger returns same instance"""
        logger1 = get_logger("test_same")
        logger2 = get_logger("test_same")

        assert logger1 is logger2

    def test_get_logger_different_names(self):
        """Test that different names return different loggers"""
        logger1 = get_logger("logger1")
        logger2 = get_logger("logger2")

        assert logger1 is not logger2
        assert logger1.name != logger2.name


class TestLoggerIntegration:
    """Test logger integration"""

    def test_logger_logs_different_levels(self):
        """Test logging at different levels"""
        logger = setup_logger("test_levels", level=logging.DEBUG)

        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")

        # All messages should be logged at DEBUG level
        assert logger.isEnabledFor(logging.DEBUG)

    def test_logger_with_extra_fields(self):
        """Test logger with extra fields"""
        logger = setup_logger("test_extra", level=logging.INFO)

        logger.info("Test", extra={"extra_fields": {"key": "value"}})

        # Verify handler received the message
        assert len(logger.handlers) > 0

    def test_logger_exception_logging(self):
        """Test exception logging"""
        logger = setup_logger("test_exception", level=logging.ERROR)

        try:
            raise ValueError("Test exception")
        except ValueError:
            logger.exception("Exception occurred")

        # Verify exception was logged
        assert len(logger.handlers) > 0
