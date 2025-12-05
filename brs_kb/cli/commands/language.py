#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Language command
"""

import argparse
from .base import BaseCommand
from brs_kb.i18n import set_language, get_current_language, get_supported_languages


class LanguageCommand(BaseCommand):
    """Manage language settings"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for language command"""
        parser = subparsers.add_parser("language", help="Set or list supported languages")
        parser.add_argument("language", nargs="?", help="Language code (e.g., ru, en)")
        parser.add_argument("--list", action="store_true", help="List supported languages")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute language command"""
        if args.list:
            languages = get_supported_languages()
            print("Supported languages:")
            for lang in languages:
                current = " (current)" if lang == get_current_language() else ""
                print(f"  - {lang}{current}")
            return 0

        if args.language:
            try:
                result = set_language(args.language)
                if result:
                    print(f"Language set to: {args.language}")
                    return 0
                else:
                    print(f"Error: Unsupported language '{args.language}'")
                    return 1
            except Exception as e:
                print(f"Error: {e}")
                return 1

        print(f"Current language: {get_current_language()}")
        return 0

