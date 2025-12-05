#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Migrate command - migrate from in-memory to SQLite
"""

import argparse
from .base import BaseCommand
from brs_kb.payloads_db import PAYLOAD_DATABASE
from brs_kb.payloads_db_sqlite import get_database
from brs_kb.logger import get_logger

logger = get_logger("brs_kb.cli.migrate")


class MigrateCommand(BaseCommand):
    """Migrate payloads from in-memory to SQLite database"""

    def add_parser(self, subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
        """Add parser for migrate command"""
        parser = subparsers.add_parser("migrate", help="Migrate payloads to SQLite database")
        parser.add_argument("--force", action="store_true", help="Force migration even if database exists")
        return parser

    def execute(self, args: argparse.Namespace) -> int:
        """Execute migrate command"""
        try:
            db = get_database()
            stats = db.get_stats()
            
            if stats['total_payloads'] > 0 and not args.force:
                print(f"Database already contains {stats['total_payloads']} payloads.")
                print("Use --force to migrate anyway.")
                return 1

            print(f"Migrating {len(PAYLOAD_DATABASE)} payloads to SQLite...")
            db.migrate_from_memory(PAYLOAD_DATABASE)
            
            new_stats = db.get_stats()
            print(f"✅ Migration completed: {new_stats['total_payloads']} payloads migrated")
            return 0
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            print(f"Error: {e}")
            return 1


