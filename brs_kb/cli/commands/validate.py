#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Validate command
"""

import argparse

from brs_kb import validate_payload_database

from .base import BaseCommand


class ValidateCommand(BaseCommand):
    """Validate payload database integrity"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for validate command"""
        return subparsers.add_parser("validate", help="Validate payload database integrity")

    def execute(self, args: argparse.Namespace) -> int:
        """Execute validate command"""
        try:
            result = validate_payload_database()
            errors = result.get("errors", result.get("issues", []))
            # Check if valid key exists and is explicitly False, or if there are errors
            if "valid" in result and result["valid"] is False:
                print(" Database validation failed")
                if errors:
                    print(f"Issues: {errors}")
                return 1

            if errors:
                print(" Database validation failed")
                print(f"Issues: {errors}")
                return 1

            print(" Database validation passed")
            return 0
        except Exception as e:
            print(f"Error: {e}")
            return 1
