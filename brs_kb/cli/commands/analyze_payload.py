#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Analyze payload command
"""

import argparse
import json

from brs_kb.exceptions import ValidationError
from brs_kb.reverse_map import find_contexts_for_payload
from brs_kb.validation import validate_payload

from .base import BaseCommand


class AnalyzePayloadCommand(BaseCommand):
    """Analyze XSS payload"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for analyze-payload command"""
        parser = subparsers.add_parser("analyze-payload", help="Analyze XSS payload")
        parser.add_argument("payload", help="Payload to analyze")
        parser.add_argument("--json", action="store_true", help="Output as JSON")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute analyze-payload command"""
        try:
            validated_payload = validate_payload(args.payload)
            result = find_contexts_for_payload(validated_payload)

            if args.json:
                print(json.dumps(result, indent=2))
                return 0

            print("Payload Analysis")
            print("=" * 50)
            print(f"Payload: {validated_payload[:80]}...")
            print()

            print(f"Detected Contexts: {', '.join(result.get('contexts', []))}")
            print(f"Confidence: {result.get('confidence', 0.0):.2f}")
            print(f"Severity: {result.get('severity', 'unknown')}")
            print()

            if result.get("patterns_matched"):
                print("Matched Patterns:")
                for pattern in result["patterns_matched"][:3]:
                    print(f"  - {pattern.get('pattern', '')[:50]}...")
                    print(f"    Contexts: {', '.join(pattern.get('contexts', []))}")
                    print(f"    Confidence: {pattern.get('confidence', 0.0):.2f}")
                print()

            if result.get("recommended_defenses"):
                print("Recommended Defenses:")
                for defense in result["recommended_defenses"][:5]:
                    defense_name = defense.get("defense", "")
                    priority = defense.get("priority", 0)
                    print(f"  - {defense_name} (priority: {priority})")
                print()

            return 0
        except ValidationError as e:
            print(f"Validation Error: {e.message}")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1
