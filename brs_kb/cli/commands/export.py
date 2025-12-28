#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Export command
"""

import argparse
import json

from brs_kb import (
    generate_payload_report,
    get_all_contexts,
    get_all_payloads,
    get_vulnerability_details,
)

from .base import BaseCommand


class ExportCommand(BaseCommand):
    """Export data in various formats"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for export command"""
        parser = subparsers.add_parser("export", help="Export data in various formats")
        parser.add_argument(
            "type", choices=["payloads", "contexts", "report"], help="Data type to export"
        )
        parser.add_argument(
            "--format", "-f", choices=["json", "text"], default="json", help="Export format"
        )
        parser.add_argument("--output", "-o", help="Output file (default: stdout)")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute export command"""
        try:
            if args.type == "payloads":
                payloads = get_all_payloads()
                if args.format == "json":
                    data = json.dumps(
                        [
                            {
                                "payload": (
                                    p.payload if hasattr(p, "payload") else p.get("payload", "")
                                ),
                                "contexts": (
                                    p.contexts if hasattr(p, "contexts") else p.get("contexts", [])
                                ),
                                "severity": (
                                    p.severity
                                    if hasattr(p, "severity")
                                    else p.get("severity", "unknown")
                                ),
                            }
                            for p in payloads
                        ],
                        indent=2,
                    )
                else:
                    data = "\n".join(
                        [
                            p.payload if hasattr(p, "payload") else p.get("payload", "")
                            for p in payloads
                        ]
                    )
            elif args.type == "contexts":
                contexts = get_all_contexts()
                if args.format == "json":
                    data = json.dumps(
                        {ctx: get_vulnerability_details(ctx) for ctx in contexts}, indent=2
                    )
                else:
                    data = "\n".join(contexts)
            elif args.type == "report":
                report = generate_payload_report()
                if args.format == "json":
                    data = json.dumps({"report": report}, indent=2)
                else:
                    data = report

            if args.output:
                with open(args.output, "w") as f:
                    f.write(data)
                print(f"Exported to {args.output}")
            else:
                print(data)
            return 0
        except Exception as e:
            print(f"Error: {e}")
            return 1
