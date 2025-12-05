#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Database migration system for SQLite payloads database
"""

import sqlite3
from typing import List, Dict, Any
from pathlib import Path

from brs_kb.logger import get_logger
from brs_kb.exceptions import DatabaseError

logger = get_logger("brs_kb.migrations")


class Migration:
    """Database migration"""

    def __init__(self, version: str, description: str, up_sql: str, down_sql: str = ""):
        """
        Initialize migration

        Args:
            version: Migration version (e.g., "001_initial")
            description: Migration description
            up_sql: SQL to apply migration
            down_sql: SQL to rollback migration
        """
        self.version = version
        self.description = description
        self.up_sql = up_sql
        self.down_sql = down_sql

    def apply(self, connection: sqlite3.Connection):
        """Apply migration"""
        cursor = connection.cursor()
        try:
            cursor.executescript(self.up_sql)
            cursor.execute(
                "INSERT INTO migrations (version) VALUES (?)",
                (self.version,),
            )
            connection.commit()
            logger.info("Applied migration: %s - %s", self.version, self.description)
        except sqlite3.Error as e:
            connection.rollback()
            logger.error("Failed to apply migration %s: %s", self.version, e)
            raise DatabaseError(f"Migration failed: {e}")

    def rollback(self, connection: sqlite3.Connection):
        """Rollback migration"""
        if not self.down_sql:
            logger.warning("No rollback SQL for migration %s", self.version)
            return

        cursor = connection.cursor()
        try:
            cursor.executescript(self.down_sql)
            cursor.execute("DELETE FROM migrations WHERE version = ?", (self.version,))
            connection.commit()
            logger.info("Rolled back migration: %s", self.version)
        except sqlite3.Error as e:
            connection.rollback()
            logger.error("Failed to rollback migration %s: %s", self.version, e)
            raise DatabaseError(f"Rollback failed: {e}")


# Define migrations
MIGRATIONS: List[Migration] = [
    Migration(
        version="001_initial",
        description="Initial payloads table creation",
        up_sql="""
        CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL,
            contexts TEXT NOT NULL,
            severity TEXT NOT NULL,
            tags TEXT NOT NULL,
            waf_evasion INTEGER NOT NULL DEFAULT 0,
            browser_support TEXT NOT NULL,
            cvss_score REAL,
            cwe_id TEXT,
            owasp_category TEXT,
            last_updated TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_payloads_contexts ON payloads(contexts);
        CREATE INDEX IF NOT EXISTS idx_payloads_severity ON payloads(severity);
        CREATE INDEX IF NOT EXISTS idx_payloads_tags ON payloads(tags);
        CREATE INDEX IF NOT EXISTS idx_payloads_waf_evasion ON payloads(waf_evasion);
        
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL UNIQUE,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """,
        down_sql="""
        DROP INDEX IF EXISTS idx_payloads_waf_evasion;
        DROP INDEX IF EXISTS idx_payloads_tags;
        DROP INDEX IF EXISTS idx_payloads_severity;
        DROP INDEX IF EXISTS idx_payloads_contexts;
        DROP TABLE IF EXISTS payloads;
        """,
    ),
]


def get_applied_migrations(connection: sqlite3.Connection) -> List[str]:
    """
    Get list of applied migrations

    Args:
        connection: Database connection

    Returns:
        List of migration versions
    """
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT version FROM migrations ORDER BY version")
        return [row[0] for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        # Migrations table doesn't exist yet
        return []


def run_migrations(db_path: str) -> int:
    """
    Run all pending migrations

    Args:
        db_path: Path to SQLite database

    Returns:
        Number of migrations applied
    """
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    try:
        # Ensure migrations table exists
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL UNIQUE,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()

        applied = get_applied_migrations(connection)
        applied_count = 0

        for migration in MIGRATIONS:
            if migration.version not in applied:
                migration.apply(connection)
                applied_count += 1

        logger.info("Applied %d migrations", applied_count)
        return applied_count
    finally:
        connection.close()


def get_migration_status(db_path: str) -> Dict[str, Any]:
    """
    Get migration status

    Args:
        db_path: Path to SQLite database

    Returns:
        Dictionary with migration status
    """
    if not Path(db_path).exists():
        return {
            "database_exists": False,
            "applied_migrations": [],
            "pending_migrations": [m.version for m in MIGRATIONS],
            "total_migrations": len(MIGRATIONS),
        }

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    try:
        applied = get_applied_migrations(connection)
        all_versions = [m.version for m in MIGRATIONS]
        pending = [v for v in all_versions if v not in applied]

        return {
            "database_exists": True,
            "applied_migrations": applied,
            "pending_migrations": pending,
            "total_migrations": len(MIGRATIONS),
            "is_up_to_date": len(pending) == 0,
        }
    finally:
        connection.close()

