#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

BRS-KB Command Line Interface: Backward compatibility wrapper
This file maintains backward compatibility while the actual implementation
has been moved to brs_kb/cli/ package
"""

# Import from refactored package for backward compatibility
from brs_kb.cli import BRSKBCLI


# Export for backward compatibility
__all__ = ["BRSKBCLI"]


def main():
    """Main entry point"""
    import sys

    cli = BRSKBCLI()
    sys.exit(cli.run())
