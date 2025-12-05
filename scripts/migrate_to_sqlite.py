#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Migration script to migrate payloads from in-memory to SQLite
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from brs_kb.payloads_db_sqlite import migrate_from_memory
from brs_kb.logger import setup_logger

logger = setup_logger("migrate", level=20, json_format=False)


def main():
    """Main migration function"""
    print("=== BRS-KB Payloads Migration to SQLite ===")
    print()

    try:
        migrated = migrate_from_memory()
        print(f"✓ Successfully migrated {migrated} payloads to SQLite")
        print(f"✓ Database location: brs_kb/data/payloads.db")
        return 0
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        logger.error("Migration failed: %s", e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

