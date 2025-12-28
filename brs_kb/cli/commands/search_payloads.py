#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Search payloads command
"""

import argparse

from brs_kb import search_payloads
from brs_kb.exceptions import ValidationError
from brs_kb.validation import validate_search_query

from .base import BaseCommand


class SearchPayloadsCommand(BaseCommand):
    """Search payloads in database"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for search-payloads command"""
        parser = subparsers.add_parser("search-payloads", help="Search payloads in database")
        parser.add_argument("query", help="Search query")
        parser.add_argument("--limit", type=int, default=10, help="Maximum results (default: 10)")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute search-payloads command"""
        try:
            validated_query = validate_search_query(args.query)
            results = search_payloads(validated_query)

            if not results:
                print(f"No payloads found for query: {validated_query}")
                return 1

            print(f"Found {len(results)} payloads (showing top {args.limit}):")
            print("=" * 50)

            for i, result in enumerate(results[: args.limit], 1):
                if isinstance(result, tuple):
                    payload, score = result
                    payload_str = (
                        payload.payload
                        if hasattr(payload, "payload")
                        else payload.get("payload", "")
                    )
                else:
                    payload_str = result.get("payload", "")
                    score = result.get("relevance_score", 0.0)

                print(f"{i}. {payload_str[:70]}...")
                print(f"   Relevance: {score:.2f}")
                print()

            return 0
        except ValidationError as e:
            print(f"Validation Error: {e.message}")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1
