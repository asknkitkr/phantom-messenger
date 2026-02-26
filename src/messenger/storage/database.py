"""
SQLCipher-encrypted database manager.

The entire database (messages, contacts, metadata) is encrypted with
AES-256-CBC via SQLCipher. The encryption key is derived from the
user's master passphrase.

If SQLCipher is not available (missing C library), falls back to
standard sqlite3 with a warning — useful for development/testing.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional

from messenger.config import DB_PATH, SQLCIPHER_KDF_ITER
from messenger.storage.models import (
    Contact,
    Conversation,
    Message,
    MessageDirection,
    MessageStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try to import sqlcipher3; fall back to sqlite3 for development
# ---------------------------------------------------------------------------
try:
    import sqlcipher3 as sqlite3  # type: ignore[import-untyped]

    HAS_SQLCIPHER = True
    logger.info("Using SQLCipher for encrypted database.")
except ImportError:
    import sqlite3  # type: ignore[no-redef]

    HAS_SQLCIPHER = False
    logger.warning(
        "sqlcipher3 not found — falling back to plain sqlite3. "
        "Install sqlcipher3 for encrypted storage: pip install sqlcipher3"
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    public_key  TEXT NOT NULL DEFAULT '',
    verify_key  TEXT NOT NULL DEFAULT '',
    last_seen   REAL NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    contact_id  TEXT NOT NULL,
    content     TEXT NOT NULL DEFAULT '',
    timestamp   REAL NOT NULL DEFAULT 0,
    direction   TEXT NOT NULL DEFAULT 'sent',
    status      TEXT NOT NULL DEFAULT 'pending',
    is_read     INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_contact
    ON messages(contact_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_contacts_public_key
    ON contacts(public_key);
"""


class DatabaseManager:
    """Thread-safe, encrypted SQLite database for storing contacts and messages.

    Usage::

        db = DatabaseManager()
        db.open("my_passphrase")
        db.save_contact(contact)
        db.save_message(message)
        messages = db.get_messages("contact-id")
        db.close()
    """

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _is_plain_sqlite(self) -> bool:
        """Check if the existing DB file is a plain (unencrypted) SQLite file.

        SQLite files start with the magic string 'SQLite format 3\\0'.
        SQLCipher-encrypted files start with random encrypted bytes.
        """
        if not self._db_path.exists():
            return False
        try:
            with open(self._db_path, "rb") as f:
                header = f.read(16)
            return header[:15] == b"SQLite format 3"
        except Exception:
            return False

    def open(self, passphrase: str) -> bool:
        """Open (or create) the encrypted database.

        Handles the common conflict where a plain SQLite database was
        created before sqlcipher3 was installed. In that case, the old
        file is backed up and a fresh encrypted database is created.

        Args:
            passphrase: The user's master passphrase. Used as the SQLCipher key.

        Returns:
            True if the database was opened successfully.
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Detect and resolve SQLCipher ↔ plain SQLite conflict
        if HAS_SQLCIPHER and self._db_path.exists() and self._is_plain_sqlite():
            logger.warning(
                "Found a plain (unencrypted) database but SQLCipher is active. "
                "Backing up old database and creating a fresh encrypted one."
            )
            backup_path = self._db_path.with_suffix(".db.bak")
            try:
                os.replace(str(self._db_path), str(backup_path))
                logger.info("Old database backed up to: %s", backup_path)
            except OSError as exc:
                logger.error("Failed to back up old database: %s", exc)
                return False

        self._conn = sqlite3.connect(str(self._db_path))

        # SQLCipher requires PRAGMA key to be the FIRST statement
        if HAS_SQLCIPHER:
            safe_pass = passphrase.replace("'", "''")
            self._conn.execute(f"PRAGMA key='{safe_pass}'")
            self._conn.execute(f"PRAGMA kdf_iter={SQLCIPHER_KDF_ITER}")

        # Verify we can read the database (will fail with wrong passphrase)
        # journal_mode and foreign_keys also trigger reads, so they must
        # be inside this block to catch decryption failures.
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("SELECT count(*) FROM sqlite_master")
        except Exception as exc:
            logger.error("Failed to open database — wrong passphrase? %s", exc)
            self._conn.close()
            self._conn = None
            return False

        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        return True

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not open. Call open() first.")
        return self._conn

    # ------------------------------------------------------------------
    # Contacts
    # ------------------------------------------------------------------

    def save_contact(self, contact: Contact) -> None:
        """Insert or update a contact."""
        self._db.execute(
            """
            INSERT INTO contacts (id, name, public_key, verify_key, last_seen, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                public_key=excluded.public_key,
                verify_key=excluded.verify_key,
                last_seen=excluded.last_seen
            """,
            (
                contact.id,
                contact.name,
                contact.public_key,
                contact.verify_key,
                contact.last_seen,
                contact.created_at,
            ),
        )
        self._db.commit()

    def get_contact(self, contact_id: str) -> Contact | None:
        """Fetch a single contact by ID."""
        row = self._db.execute(
            "SELECT id, name, public_key, verify_key, last_seen, created_at "
            "FROM contacts WHERE id=?",
            (contact_id,),
        ).fetchone()
        return self._row_to_contact(row) if row else None

    def get_contact_by_public_key(self, public_key: str) -> Contact | None:
        """Find a contact by their X25519 public key."""
        row = self._db.execute(
            "SELECT id, name, public_key, verify_key, last_seen, created_at "
            "FROM contacts WHERE public_key=?",
            (public_key,),
        ).fetchone()
        return self._row_to_contact(row) if row else None

    def get_all_contacts(self) -> list[Contact]:
        """Return all contacts ordered by last activity."""
        rows = self._db.execute(
            "SELECT id, name, public_key, verify_key, last_seen, created_at "
            "FROM contacts ORDER BY last_seen DESC"
        ).fetchall()
        return [self._row_to_contact(r) for r in rows]

    def delete_contact(self, contact_id: str) -> None:
        """Delete a contact and all associated messages."""
        self._db.execute("DELETE FROM contacts WHERE id=?", (contact_id,))
        self._db.commit()

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def save_message(self, message: Message) -> None:
        """Insert or update a message."""
        self._db.execute(
            """
            INSERT INTO messages (id, contact_id, content, timestamp, direction, status, is_read)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                content=excluded.content,
                status=excluded.status,
                is_read=excluded.is_read
            """,
            (
                message.id,
                message.contact_id,
                message.content,
                message.timestamp,
                message.direction.value,
                message.status.value,
                1 if message.is_read else 0,
            ),
        )
        self._db.commit()

    def get_messages(
        self,
        contact_id: str,
        limit: int = 100,
        before: float | None = None,
    ) -> list[Message]:
        """Fetch messages for a contact, newest first.

        Args:
            contact_id: The contact ID.
            limit: Maximum number of messages to return.
            before: Only return messages before this Unix timestamp (pagination).
        """
        if before is not None:
            rows = self._db.execute(
                "SELECT id, contact_id, content, timestamp, direction, status, is_read "
                "FROM messages WHERE contact_id=? AND timestamp<? "
                "ORDER BY timestamp DESC LIMIT ?",
                (contact_id, before, limit),
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT id, contact_id, content, timestamp, direction, status, is_read "
                "FROM messages WHERE contact_id=? "
                "ORDER BY timestamp DESC LIMIT ?",
                (contact_id, limit),
            ).fetchall()

        # Return in chronological order (oldest first)
        messages = [self._row_to_message(r) for r in rows]
        messages.reverse()
        return messages

    def mark_messages_read(self, contact_id: str) -> None:
        """Mark all received messages from a contact as read."""
        self._db.execute(
            "UPDATE messages SET is_read=1 "
            "WHERE contact_id=? AND direction='received' AND is_read=0",
            (contact_id,),
        )
        self._db.commit()

    def update_message_status(self, message_id: str, status: MessageStatus) -> None:
        """Update the delivery status of a message."""
        self._db.execute(
            "UPDATE messages SET status=? WHERE id=?",
            (status.value, message_id),
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # Conversations
    # ------------------------------------------------------------------

    def get_conversations(self) -> list[Conversation]:
        """Get all conversations with their latest messages."""
        contacts = self.get_all_contacts()
        conversations = []
        for contact in contacts:
            messages = self.get_messages(contact.id, limit=50)
            conversations.append(Conversation(contact=contact, messages=messages))

        # Sort by most recent activity
        conversations.sort(
            key=lambda c: c.last_message.timestamp if c.last_message else 0,
            reverse=True,
        )
        return conversations

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_contact(row: tuple) -> Contact:
        return Contact(
            id=row[0],
            name=row[1],
            public_key=row[2],
            verify_key=row[3],
            last_seen=row[4],
            created_at=row[5],
        )

    @staticmethod
    def _row_to_message(row: tuple) -> Message:
        return Message(
            id=row[0],
            contact_id=row[1],
            content=row[2],
            timestamp=row[3],
            direction=MessageDirection(row[4]),
            status=MessageStatus(row[5]),
            is_read=bool(row[6]),
        )
