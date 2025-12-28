#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Info command
"""

import argparse
import json

from brs_kb import get_database_info, get_kb_info
from brs_kb.reverse_map import get_reverse_map_info

from .base import BaseCommand


class InfoCommand(BaseCommand):
    """Show system information"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for info command"""
        parser = subparsers.add_parser("info", help="Show system information")
        parser.add_argument("--json", action="store_true", help="Output as JSON")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute info command"""
        kb_info = get_kb_info()
        db_info = get_database_info()
        rm_info = get_reverse_map_info()

        info = {
            "knowledge_base": kb_info,
            "database": db_info,
            "reverse_mapping": rm_info,
        }

        if args.json:
            print(json.dumps(info, indent=2))
            return 0

        print("BRS-KB System Information")
        print("=" * 50)
        print(f"Version: {kb_info.get('version', 'unknown')}")
        print(f"Contexts: {kb_info.get('total_contexts', 0)}")
        print(f"Payloads: {db_info.get('total_payloads', 0)}")
        print(f"Database Type: {db_info.get('database_type', 'in-memory')}")
        print(f"Reverse Mapping Patterns: {rm_info.get('patterns_count', 0)}")
        print()

        return 0
