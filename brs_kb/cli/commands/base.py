#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Base command class for CLI commands
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseCommand(ABC):
    """Base class for CLI commands"""

    @abstractmethod
    def execute(self, args: Any) -> int:
        """Execute the command"""
        pass

    @abstractmethod
    def add_parser(self, subparsers: Any) -> Any:
        """Add command parser to subparsers"""
        pass
