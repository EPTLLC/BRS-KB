#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Generate report command
"""

import argparse

from brs_kb import generate_payload_report

from .base import BaseCommand


class GenerateReportCommand(BaseCommand):
    """Generate comprehensive system report"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for generate-report command"""
        return subparsers.add_parser("generate-report", help="Generate comprehensive system report")

    def execute(self, args: argparse.Namespace) -> int:
        """Execute generate-report command"""
        try:
            report = generate_payload_report()
            print(report)
            return 0
        except Exception as e:
            print(f"Error generating report: {e}")
            return 1
