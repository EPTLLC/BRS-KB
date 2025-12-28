#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Structured logging module for BRS-KB
Provides JSON-formatted logging for better integration with SIEM systems
"""

import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module_name": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        # Add context if present
        if hasattr(record, "context"):
            log_data["context"] = record.context

        return json.dumps(log_data, ensure_ascii=False)


def setup_logger(
    name: str = "brs_kb",
    level: int = logging.INFO,
    json_format: bool = True,
    output_file: Optional[str] = None,
) -> logging.Logger:
    """
    Setup structured logger for BRS-KB

    Args:
        name: Logger name
        level: Logging level
        json_format: Use JSON formatting (default: True)
        output_file: Optional file path for logging

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers.clear()

    # Create handler
    if output_file:
        handler = logging.FileHandler(output_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stdout)

    # Set formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get logger instance

    Args:
        name: Optional logger name (default: 'brs_kb')

    Returns:
        Logger instance
    """
    logger_name = name or "brs_kb"
    logger = logging.getLogger(logger_name)

    # Setup if not configured
    if not logger.handlers:
        logger = setup_logger(logger_name)

    return logger


# Default logger instance
default_logger = setup_logger()
