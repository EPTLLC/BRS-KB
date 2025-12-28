#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

BRS-KB Command Line Interface
Refactored to use command pattern
"""

import sys
from typing import List, Optional

from .parser import create_parser


class BRSKBCLI:
    """BRS-KB Command Line Interface"""

    def __init__(self):
        self.parser, self.commands = create_parser()

    def run(self, args: Optional[List[str]] = None) -> int:
        """Run CLI with given arguments"""
        try:
            parsed_args = self.parser.parse_args(args)

            if not parsed_args.command:
                self.parser.print_help()
                return 1

            # Get command instance
            if parsed_args.command in self.commands:
                return self.commands[parsed_args.command].execute(parsed_args)

            self.parser.print_help()
            return 1

        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return 1
        except Exception as e:
            from brs_kb.exceptions import BRSKBError

            if isinstance(e, BRSKBError):
                print(f"Error: {e.message}")
                if hasattr(e, "context"):
                    print(f"Context: {e.context}")
                if hasattr(e, "details"):
                    print(f"Details: {e.details}")
            else:
                print(f"Error: {e}")
            return 1


def main():
    """Main entry point"""
    cli = BRSKBCLI()
    sys.exit(cli.run())
