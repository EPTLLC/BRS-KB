#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

SQLite database module for payloads storage
Provides persistent storage for payload database
"""

import sqlite3
import json
import os
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

from brs_kb.logger import get_logger
from brs_kb.exceptions import DatabaseError

logger = get_logger("brs_kb.payloads_db_sqlite")


@dataclass
class PayloadEntry:
    """Payload entry dataclass matching in-memory structure"""

    payload: str
    contexts: List[str]
    severity: str
    cvss_score: float
    description: str
    tags: List[str] = None
    bypasses: List[str] = None
    encoding: str = "none"
    browser_support: List[str] = None
    waf_evasion: bool = False
    tested_on: List[str] = None
    reliability: str = "high"
    last_updated: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    def __post_init__(self):
        """Initialize default values"""
        if self.tags is None:
            self.tags = []
        if self.bypasses is None:
            self.bypasses = []
        if self.browser_support is None:
            self.browser_support = []
        if self.tested_on is None:
            self.tested_on = []


class PayloadDatabase:
    """SQLite database for payloads"""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize SQLite database

        Args:
            db_path: Path to SQLite database file (default: brs_kb/data/payloads.db)
        """
        if db_path is None:
            # Default path: brs_kb/data/payloads.db
            base_dir = Path(__file__).parent
            data_dir = base_dir / "data"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "payloads.db")

        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None
        
        # Run migrations
        from brs_kb.migrations import run_migrations
        run_migrations(db_path)
        
        self._ensure_connection()

    def _ensure_connection(self):
        """Ensure database connection is established"""
        if self._connection is None:
            try:
                self._connection = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=10.0,
                )
                self._connection.row_factory = sqlite3.Row
                logger.info("Connected to SQLite database: %s", self.db_path)
            except sqlite3.Error as e:
                logger.error("Failed to connect to SQLite database: %s", e)
                raise DatabaseError(f"Database connection failed: {e}")

    def _serialize_list(self, value: List[str]) -> str:
        """Serialize list to JSON string"""
        return json.dumps(value, ensure_ascii=False)

    def _deserialize_list(self, value: str) -> List[str]:
        """Deserialize JSON string to list"""
        if not value:
            return []
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value.split(",") if "," in value else [value]

    def add_payload(self, entry: PayloadEntry) -> int:
        """
        Add payload to database

        Args:
            entry: PayloadEntry instance

        Returns:
            Inserted payload ID
        """
        self._ensure_connection()
        cursor = self._connection.cursor()

        try:
            cursor.execute(
                """
                INSERT OR REPLACE INTO payloads (
                    payload, description, contexts, severity, tags,
                    waf_evasion, browser_support, cvss_score, cwe_id,
                    owasp_category, last_updated, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    entry.payload,
                    entry.description,
                    self._serialize_list(entry.contexts),
                    entry.severity,
                    self._serialize_list(entry.tags or []),
                    1 if entry.waf_evasion else 0,
                    self._serialize_list(entry.browser_support or []),
                    entry.cvss_score,
                    getattr(entry, 'cwe_id', None),
                    getattr(entry, 'owasp_category', None),
                    entry.last_updated,
                ),
            )
            self._connection.commit()
            payload_id = cursor.lastrowid
            logger.debug("Added payload to database: %s", entry.payload[:50])
            return payload_id
        except sqlite3.Error as e:
            self._connection.rollback()
            logger.error("Failed to add payload: %s", e)
            raise DatabaseError(f"Failed to add payload: {e}")

    def get_payload(self, payload: str) -> Optional[PayloadEntry]:
        """
        Get payload by payload string

        Args:
            payload: Payload string

        Returns:
            PayloadEntry or None if not found
        """
        self._ensure_connection()
        cursor = self._connection.cursor()

        cursor.execute("SELECT * FROM payloads WHERE payload = ?", (payload,))
        row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_entry(row)

    def get_all_payloads(self) -> List[PayloadEntry]:
        """
        Get all payloads from database

        Returns:
            List of PayloadEntry instances
        """
        self._ensure_connection()
        cursor = self._connection.cursor()

        cursor.execute("SELECT * FROM payloads ORDER BY id")
        rows = cursor.fetchall()

        return [self._row_to_entry(row) for row in rows]

    def search_payloads(
        self, query: str, limit: int = 100
    ) -> List[Tuple[PayloadEntry, float]]:
        """
        Search payloads by query

        Args:
            query: Search query string
            limit: Maximum number of results

        Returns:
            List of tuples (PayloadEntry, relevance_score)
        """
        self._ensure_connection()
        cursor = self._connection.cursor()

        query_lower = query.lower()
        results = []

        # Search in payload, description, tags, contexts
        cursor.execute(
            """
            SELECT *, 
                CASE
                    WHEN LOWER(payload) LIKE ? THEN 1.0
                    WHEN LOWER(description) LIKE ? THEN 0.8
                    WHEN LOWER(tags) LIKE ? THEN 0.6
                    WHEN LOWER(contexts) LIKE ? THEN 0.4
                    ELSE 0.0
                END as relevance
            FROM payloads
            WHERE LOWER(payload) LIKE ?
               OR LOWER(description) LIKE ?
               OR LOWER(tags) LIKE ?
               OR LOWER(contexts) LIKE ?
            ORDER BY relevance DESC
            LIMIT ?
            """,
            (
                f"%{query_lower}%",
                f"%{query_lower}%",
                f"%{query_lower}%",
                f"%{query_lower}%",
                f"%{query_lower}%",
                f"%{query_lower}%",
                f"%{query_lower}%",
                f"%{query_lower}%",
                limit,
            ),
        )

        rows = cursor.fetchall()
        for row in rows:
            entry = self._row_to_entry(row)
            relevance = float(row["relevance"])
            if relevance > 0:
                results.append((entry, relevance))

        return results

    def get_payloads_by_context(self, context: str) -> List[PayloadEntry]:
        """Get payloads by context"""
        self._ensure_connection()
        cursor = self._connection.cursor()

        cursor.execute(
            "SELECT * FROM payloads WHERE LOWER(contexts) LIKE ?",
            (f"%{context.lower()}%",),
        )
        rows = cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    def get_payloads_by_severity(self, severity: str) -> List[PayloadEntry]:
        """Get payloads by severity"""
        self._ensure_connection()
        cursor = self._connection.cursor()

        cursor.execute(
            "SELECT * FROM payloads WHERE LOWER(severity) = ?",
            (severity.lower(),),
        )
        rows = cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    def get_payloads_by_tag(self, tag: str) -> List[PayloadEntry]:
        """Get payloads by tag"""
        self._ensure_connection()
        cursor = self._connection.cursor()

        cursor.execute(
            "SELECT * FROM payloads WHERE LOWER(tags) LIKE ?",
            (f"%{tag.lower()}%",),
        )
        rows = cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    def get_waf_bypass_payloads(self) -> List[PayloadEntry]:
        """Get WAF bypass payloads"""
        self._ensure_connection()
        cursor = self._connection.cursor()

        cursor.execute("SELECT * FROM payloads WHERE waf_evasion = 1")
        rows = cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        self._ensure_connection()
        cursor = self._connection.cursor()

        stats = {}

        # Total payloads
        cursor.execute("SELECT COUNT(*) as count FROM payloads")
        stats["total_payloads"] = cursor.fetchone()["count"]

        # By severity
        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM payloads GROUP BY severity"
        )
        stats["by_severity"] = {row["severity"]: row["count"] for row in cursor.fetchall()}

        # WAF bypass count
        cursor.execute("SELECT COUNT(*) as count FROM payloads WHERE waf_evasion = 1")
        stats["waf_bypass_count"] = cursor.fetchone()["count"]

        # Unique contexts
        cursor.execute("SELECT DISTINCT contexts FROM payloads")
        all_contexts = set()
        for row in cursor.fetchall():
            contexts = self._deserialize_list(row["contexts"])
            all_contexts.update(contexts)
        stats["contexts_covered"] = sorted(list(all_contexts))

        # Unique tags
        cursor.execute("SELECT DISTINCT tags FROM payloads")
        all_tags = set()
        for row in cursor.fetchall():
            tags = self._deserialize_list(row["tags"])
            all_tags.update(tags)
        stats["tags_found"] = sorted(list(all_tags))

        return stats

    def _row_to_entry(self, row: sqlite3.Row) -> PayloadEntry:
        """Convert database row to PayloadEntry"""
        return PayloadEntry(
            payload=row["payload"],
            contexts=self._deserialize_list(row["contexts"]),
            severity=row["severity"],
            cvss_score=row["cvss_score"] or 0.0,
            description=row["description"],
            tags=self._deserialize_list(row["tags"]),
            bypasses=[],  # Not stored in DB
            encoding="none",  # Not stored in DB
            browser_support=self._deserialize_list(row["browser_support"]),
            waf_evasion=bool(row["waf_evasion"]),
            tested_on=[],  # Not stored in DB
            reliability="high",  # Not stored in DB
            last_updated=row["last_updated"],
            cwe_id=row["cwe_id"],
            owasp_category=row["owasp_category"],
        )

    def migrate_from_memory(self, in_memory_db: Dict[str, PayloadEntry]) -> int:
        """
        Migrate payloads from an in-memory dictionary to SQLite
        
        Args:
            in_memory_db: Dictionary of payload_id -> PayloadEntry
            
        Returns:
            Number of migrated payloads
        """
        migrated = 0
        for payload_id, entry in in_memory_db.items():
            try:
                # Check if payload already exists
                existing = self.get_payload(entry.payload)
                if existing is None:
                    self.add_payload(entry)
                    migrated += 1
            except Exception as e:
                logger.warning("Failed to migrate payload %s: %s", payload_id, e)
        
        logger.info("Migrated %d payloads to SQLite database", migrated)
        return migrated

    def close(self):
        """Close database connection"""
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.info("Closed database connection")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Global database instance
_db_instance: Optional[PayloadDatabase] = None


def get_database(db_path: Optional[str] = None) -> PayloadDatabase:
    """
    Get global database instance

    Args:
        db_path: Optional database path

    Returns:
        PayloadDatabase instance
    """
    global _db_instance
    if _db_instance is None:
        _db_instance = PayloadDatabase(db_path)
    return _db_instance


def migrate_from_memory() -> int:
    """
    Migrate payloads from in-memory PAYLOAD_DATABASE to SQLite

    Returns:
        Number of migrated payloads
    """
    try:
        from brs_kb.payloads_db import PAYLOAD_DATABASE

        db = get_database()
        migrated = 0

        for payload_id, entry in PAYLOAD_DATABASE.items():
            try:
                # Check if payload already exists
                existing = db.get_payload(entry.payload)
                if existing is None:
                    db.add_payload(entry)
                    migrated += 1
            except Exception as e:
                logger.warning("Failed to migrate payload %s: %s", payload_id, e)

        logger.info("Migrated %d payloads to SQLite database", migrated)
        return migrated
    except ImportError:
        logger.warning("PAYLOAD_DATABASE not found, skipping migration")
        return 0
