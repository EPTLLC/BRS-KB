#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

CLI parser configuration
"""

import argparse

from .commands import (
    AnalyzePayloadCommand,
    ExportCommand,
    GenerateReportCommand,
    GetContextCommand,
    InfoCommand,
    ListContextsCommand,
    SearchPayloadsCommand,
    ServeCommand,
    TestPayloadCommand,
    ValidateCommand,
)


def create_parser():
    """Create argument parser with all commands"""
    parser = argparse.ArgumentParser(
        description="BRS-KB: Community XSS Knowledge Base CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  brs-kb list-contexts                    # Show all XSS contexts
  brs-kb get-context html_content         # Get HTML content XSS details
  brs-kb analyze-payload "<script>alert(1)</script>"  # Analyze payload
  brs-kb search-payloads script           # Search payloads
  brs-kb test-payload "<script>alert(1)</script>" html_content  # Test payload
  brs-kb generate-report                  # Generate comprehensive report
  brs-kb info                             # Show system information
  brs-kb serve                            # Start API server for Web UI
  brs-kb serve --port 8080                # Start API server on custom port
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Register all commands
    commands = {
        "list-contexts": ListContextsCommand(),
        "get-context": GetContextCommand(),
        "analyze-payload": AnalyzePayloadCommand(),
        "search-payloads": SearchPayloadsCommand(),
        "test-payload": TestPayloadCommand(),
        "generate-report": GenerateReportCommand(),
        "info": InfoCommand(),
        "validate": ValidateCommand(),
        "export": ExportCommand(),
        "serve": ServeCommand(),
    }

    # Add parsers for each command
    for _cmd_name, cmd_instance in commands.items():
        cmd_instance.add_parser(subparsers)

    return parser, commands
