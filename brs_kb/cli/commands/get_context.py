#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Get context command
"""

import argparse

from brs_kb import get_payloads_by_context, get_vulnerability_details
from brs_kb.exceptions import BRSKBError
from brs_kb.validation import validate_context_name

from .base import BaseCommand


class GetContextCommand(BaseCommand):
    """Get detailed information about a context"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for get-context command"""
        parser = subparsers.add_parser(
            "get-context", help="Get vulnerability details for a context"
        )
        parser.add_argument("context", help="Context name (e.g., html_content)")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute get-context command"""
        try:
            validated_context = validate_context_name(args.context)
            details = get_vulnerability_details(validated_context)

            print(f"XSS Context: {args.context.upper()}")
            print("=" * 50)
            print()

            print(f"Title: {details['title']}")
            print(f"Severity: {details['severity'].upper()}")
            print(f"CVSS Score: {details['cvss_score']}")
            print(f"Reliability: {details.get('reliability', 'unknown')}")
            print()

            if details.get("cwe"):
                print(f"CWE: {', '.join(details['cwe'])}")
            if details.get("owasp"):
                print(f"OWASP: {', '.join(details['owasp'])}")
            if details.get("tags"):
                print(f"  Tags: {', '.join(details['tags'])}")
            print()

            print(" Description:")
            print("-" * 30)
            description = details["description"].strip()
            if len(description) > 500:
                print(description[:500] + "...")
                print("   [truncated - use 'brs-kb get-context --full' for complete description]")
            else:
                print(description)
            print()

            # Show available payloads for this context
            payloads = get_payloads_by_context(args.context)
            if payloads:
                print(f"Available Payloads: {len(payloads)}")
                print("Top payloads:")
                for i, payload in enumerate(payloads[:3], 1):
                    payload_str = (
                        payload.payload
                        if hasattr(payload, "payload")
                        else payload.get("payload", "")
                    )
                    print(f"   {i}. {payload_str[:60]}...")
                print()

            return 0
        except BRSKBError as e:
            print(f"Error: {e.message}")
            if hasattr(e, "available_contexts"):
                print(f"Available contexts: {', '.join(e.available_contexts[:10])}")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1
