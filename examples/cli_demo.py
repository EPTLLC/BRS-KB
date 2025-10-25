#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Example: BRS-KB CLI Demo - Command Line Interface Usage
Demonstrates all CLI capabilities for security research and testing
"""

import sys
from io import StringIO
from contextlib import redirect_stdout

def run_cli_function(func_name: str, *args) -> str:
    """Run CLI function and capture output"""
    try:
        from brs_kb.cli import BRSKBCLI

        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()

        try:
            cli = BRSKBCLI()
            if func_name == 'info':
                cli._show_info()
            elif func_name == 'list-contexts':
                cli._list_contexts()
            elif func_name == 'get-context':
                cli._get_context(args[0] if args else 'html_content')
            elif func_name == 'analyze-payload':
                cli._analyze_payload(args[0] if args else '<script>alert(1)</script>')
            elif func_name == 'search-payloads':
                cli._search_payloads(args[0] if args else 'script', args[1] if len(args) > 1 else 5)
            elif func_name == 'test-payload':
                cli._test_payload(args[0] if args else '<script>alert(1)</script>', args[1] if len(args) > 1 else 'html_content')
            elif func_name == 'generate-report':
                cli._generate_report()
            elif func_name == 'validate':
                cli._validate_database()
            else:
                return "Unknown command"

        finally:
            sys.stdout = old_stdout

        return captured_output.getvalue()

    except Exception as e:
        return f"Error: {e}"


def main():
    """Demonstrate CLI capabilities."""

    print("=" * 80)
    print("🚀 BRS-KB CLI Tool Demonstration")
    print("=" * 80)
    print()

    # Show system information
    print("1. System Information:")
    print("-" * 80)
    output = run_cli_function('info')
    print(output)
    print()

    # List all contexts
    print("2. Available XSS Contexts:")
    print("-" * 80)
    output = run_cli_function('list-contexts')
    print(output)
    print()

    # Get specific context details
    print("3. Context Details (WebSocket XSS):")
    print("-" * 80)
    output = run_cli_function('get-context', 'websocket_xss')
    print(output[:500] + "..." if len(output) > 500 else output)
    print()

    # Analyze a payload
    print("4. Payload Analysis:")
    print("-" * 80)
    output = run_cli_function('analyze-payload', '<script>alert(1)</script>')
    print(output)
    print()

    # Search payloads
    print("5. Payload Search:")
    print("-" * 80)
    output = run_cli_function('search-payloads', 'websocket', 3)
    print(output)
    print()

    # Test payload effectiveness
    print("6. Payload Testing:")
    print("-" * 80)
    output = run_cli_function('test-payload', '<script>alert(1)</script>', 'html_content')
    print(output)
    print()

    # Generate report
    print("7. System Report (first 25 lines):")
    print("-" * 80)
    output = run_cli_function('generate-report')
    lines = output.split('\n')[:25]
    print('\n'.join(lines))
    print("... [truncated]")
    print()

    # Validate database
    print("8. Database Validation:")
    print("-" * 80)
    output = run_cli_function('validate')
    print(output)
    print()

    # Language support
    print("9. Multi-Language Support:")
    print("-" * 80)
    output = run_cli_function('language', '--list')
    print(output)
    print("Setting language to Russian...")
    output = run_cli_function('language', 'ru')
    print(output)
    print()

    print("=" * 80)
    print("✨ CLI demonstration complete!")
    print("BRS-KB CLI is ready for enterprise security workflows.")
    print("Available commands: info, list-contexts, get-context, analyze-payload,")
    print("                   search-payloads, test-payload, generate-report, validate,")
    print("                   export, language")
    print("=" * 80)


if __name__ == "__main__":
    main()
