#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

List contexts command
"""

import argparse

from brs_kb import get_kb_info, get_vulnerability_details, list_contexts

from .base import BaseCommand


class ListContextsCommand(BaseCommand):
    """List all available contexts"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for list-contexts command"""
        return subparsers.add_parser("list-contexts", help="List all available XSS contexts")

    def execute(self, args: argparse.Namespace) -> int:
        """Execute list-contexts command"""
        print("XSS Vulnerability Contexts")
        print("=" * 50)

        contexts = list_contexts()
        get_kb_info()

        print(f"Total: {len(contexts)} contexts")
        print()

        # Group contexts by type
        modern_contexts = [
            c
            for c in contexts
            if any(
                x in c
                for x in [
                    "websocket",
                    "service",
                    "webrtc",
                    "graphql",
                    "shadow",
                    "custom",
                    "http2",
                    "iframe",
                ]
            )
        ]
        legacy_contexts = [c for c in contexts if c not in modern_contexts and c != "default"]

        if modern_contexts:
            print(" Modern Web Technologies:")
            for context in sorted(modern_contexts):
                details = get_vulnerability_details(context)
                severity = details.get("severity", "unknown")
                cvss = details.get("cvss_score", 0.0)
                print(f"    {context} ({severity}, CVSS: {cvss})")
            print()

        if legacy_contexts:
            print(" Legacy/Classic Contexts:")
            for context in sorted(legacy_contexts):
                details = get_vulnerability_details(context)
                severity = details.get("severity", "unknown")
                cvss = details.get("cvss_score", 0.0)
                print(f"    {context} ({severity}, CVSS: {cvss})")
            print()

        if "default" in contexts:
            print("Fallback Context:")
            print("    default (generic XSS information)")
            print()

        return 0
