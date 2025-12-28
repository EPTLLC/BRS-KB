#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Test payload command
"""

import argparse

from brs_kb import analyze_payload_context
from brs_kb.exceptions import ValidationError
from brs_kb.validation import validate_context_name, validate_payload

from .base import BaseCommand


class TestPayloadCommand(BaseCommand):
    """Test payload effectiveness"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for test-payload command"""
        parser = subparsers.add_parser("test-payload", help="Test payload effectiveness")
        parser.add_argument("payload", help="Payload to test")
        parser.add_argument("context", help="Context to test in")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute test-payload command"""
        try:
            validated_payload = validate_payload(args.payload)
            validated_context = validate_context_name(args.context)

            result = analyze_payload_context(validated_payload, validated_context)

            print("Payload Test Results")
            print("=" * 50)
            print(f"Payload: {validated_payload[:60]}...")
            print(f"Context: {validated_context}")
            print()

            effectiveness = result.get("effectiveness_score", 0.0)
            print(f"Effectiveness: {effectiveness:.2%}")
            print(f"Browser Parsing: {result.get('browser_parsing', 'unknown')}")
            print(f"WAF Detected: {result.get('waf_detected', False)}")
            print()

            return 0
        except ValidationError as e:
            print(f"Validation Error: {e.message}")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1
