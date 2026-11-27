"""
SQLCipher-encrypted database manager.

The entire database (messages, contacts, metadata) is encrypted with
AES-256-CBC via SQLCipher. The encryption key is derived from the
user's master passphrase.

If SQLCipher is not available, opening the database fails closed rather than
writing private messages to an unencrypted SQLite file.
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
# Import SQLCipher, retaining sqlite3's connection type for static typing only.
# ---------------------------------------------------------------------------
try:
    import sqlcipher3 as sqlite3  # type: ignore[import-untyped]

    HAS_SQLCIPHER = True
    logger.info("Using SQLCipher for encrypted database.")
except ImportError:
    import sqlite3  # type: ignore[no-redef]

    HAS_SQLCIPHER = False
    logger.warning(
        "sqlcipher3 not found; encrypted storage is unavailable. "
        "Install sqlcipher3 to use the database."
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
    created_at  REAL NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS drafts (
    contact_id TEXT PRIMARY KEY,
    content TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS relay_queue (
    packet_id TEXT PRIMARY KEY,
    envelope BLOB NOT NULL,
    via TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_seen (
    packet_id TEXT PRIMARY KEY,
    seen_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
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

        if not HAS_SQLCIPHER:
            logger.error("SQLCipher is required; refusing to open an unencrypted database.")
            return False

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
        if os.name != "nt":
            os.chmod(self._db_path, 0o600)

        # SQLCipher requires PRAGMA key to be the FIRST statement
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
        self._migrate_schema()
        self._conn.commit()
        if os.name != "nt":
            os.chmod(self._db_path, 0o600)
        return True

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _migrate_schema(self) -> None:
        """Apply small, backwards-compatible schema additions."""
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(contacts)")}
        if "blocked" not in columns:
            self._db.execute(
                "ALTER TABLE contacts ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0"
            )

    def reset(self) -> None:
        """Close and remove the saved profile database."""
        self.close()
        for path in (
            self._db_path,
            self._db_path.with_name(self._db_path.name + "-wal"),
            self._db_path.with_name(self._db_path.name + "-shm"),
            self._db_path.with_name(self._db_path.name + "-journal"),
        ):
            path.unlink(missing_ok=True)

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
            INSERT INTO contacts (id, name, public_key, verify_key, last_seen, created_at, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                public_key=excluded.public_key,
                verify_key=excluded.verify_key,
                last_seen=excluded.last_seen,
                blocked=excluded.blocked
            """,
            (
                contact.id,
                contact.name,
                contact.public_key,
                contact.verify_key,
                contact.last_seen,
                contact.created_at,
                1 if contact.blocked else 0,
            ),
        )
        self._db.commit()

    def get_contact(self, contact_id: str) -> Contact | None:
        """Fetch a single contact by ID."""
        row = self._db.execute(
            "SELECT id, name, public_key, verify_key, last_seen, created_at, blocked "
            "FROM contacts WHERE id=?",
            (contact_id,),
        ).fetchone()
        return self._row_to_contact(row) if row else None

    def get_contact_by_public_key(self, public_key: str) -> Contact | None:
        """Find a contact by their X25519 public key."""
        row = self._db.execute(
            "SELECT id, name, public_key, verify_key, last_seen, created_at, blocked "
            "FROM contacts WHERE public_key=?",
            (public_key,),
        ).fetchone()
        return self._row_to_contact(row) if row else None

    def get_all_contacts(self) -> list[Contact]:
        """Return all contacts ordered by last activity."""
        rows = self._db.execute(
            "SELECT id, name, public_key, verify_key, last_seen, created_at, blocked "
            "FROM contacts ORDER BY last_seen DESC"
        ).fetchall()
        return [self._row_to_contact(r) for r in rows]

    def delete_contact(self, contact_id: str) -> None:
        """Delete a contact and all associated messages."""
        self._db.execute("DELETE FROM contacts WHERE id=?", (contact_id,))
        self._db.commit()

    def set_contact_blocked(self, contact_id: str, blocked: bool) -> None:
        """Block or unblock a contact without deleting local history."""
        self._db.execute(
            "UPDATE contacts SET blocked=? WHERE id=?", (1 if blocked else 0, contact_id)
        )
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
        self.delete_expired_messages()
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

    def get_undelivered_messages(self, contact_id: str) -> list[Message]:
        """Return outgoing messages that still need delivery confirmation."""
        rows = self._db.execute(
            "SELECT id, contact_id, content, timestamp, direction, status, is_read "
            "FROM messages WHERE contact_id=? AND direction='sent' "
            "AND status IN ('pending', 'failed') ORDER BY timestamp",
            (contact_id,),
        ).fetchall()
        return [self._row_to_message(row) for row in rows]

    def get_pending_count(self) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) FROM messages WHERE direction='sent' AND status IN ('pending', 'failed')"
        ).fetchone()
        return int(row[0])

    def get_setting(self, key: str, default: str = "") -> str:
        row = self._db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._db.commit()

    def get_message_expiry(self) -> int:
        try:
            return max(0, int(self.get_setting("message_expiry_seconds", "0")))
        except ValueError:
            return 0

    def set_message_expiry(self, seconds: int) -> None:
        self.set_setting("message_expiry_seconds", str(max(0, seconds)))
        self.delete_expired_messages()

    def delete_expired_messages(self) -> int:
        """Remove messages older than the configured expiry period."""
        expiry = self.get_message_expiry()
        if not expiry:
            return 0
        cursor = self._db.execute("DELETE FROM messages WHERE timestamp < ?", (time.time() - expiry,))
        self._db.commit()
        return cursor.rowcount

    def export_profile_data(self) -> dict:
        return {
            "contacts": [list(row) for row in self._db.execute(
                "SELECT id, name, public_key, verify_key, last_seen, created_at, blocked FROM contacts"
            )],
            "messages": [list(row) for row in self._db.execute(
                "SELECT id, contact_id, content, timestamp, direction, status, is_read FROM messages"
            )],
            "drafts": [list(row) for row in self._db.execute(
                "SELECT contact_id, content FROM drafts"
            )],
            "relay_queue": [
                [packet_id, bytes(envelope).hex(), via, created_at]
                for packet_id, envelope, via, created_at in self._db.execute(
                    "SELECT packet_id, envelope, via, created_at FROM relay_queue"
                )
            ],
            "relay_seen": [list(row) for row in self._db.execute(
                "SELECT packet_id, seen_at FROM relay_seen"
            )],
            "settings": [list(row) for row in self._db.execute(
                "SELECT key, value FROM settings"
            )],
        }

    def restore_profile_data(self, data: dict) -> None:
        with self._db:
            self._db.execute("DELETE FROM contacts")
            self._db.execute("DELETE FROM relay_queue")
            self._db.execute("DELETE FROM relay_seen")
            self._db.execute("DELETE FROM settings")
            self._db.executemany(
                "INSERT INTO contacts(id, name, public_key, verify_key, last_seen, created_at, blocked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [tuple(row) + (0,) if len(row) == 6 else row for row in data["contacts"]],
            )
            self._db.executemany(
                "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)", data["messages"]
            )
            self._db.executemany(
                "INSERT INTO drafts VALUES (?, ?)", data.get("drafts", [])
            )
            self._db.executemany(
                "INSERT INTO relay_queue VALUES (?, ?, ?, ?)",
                [
                    (packet_id, bytes.fromhex(encoded), via, created_at)
                    for packet_id, encoded, via, created_at in data.get("relay_queue", [])
                ],
            )
            self._db.executemany(
                "INSERT INTO relay_seen VALUES (?, ?)", data.get("relay_seen", [])
            )
            self._db.executemany(
                "INSERT INTO settings VALUES (?, ?)", data.get("settings", [])
            )

    def rekey(self, passphrase: str) -> None:
        safe_pass = passphrase.replace("'", "''")
        self._db.execute(f"PRAGMA rekey='{safe_pass}'")
        self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()

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

    def get_conversations(self, query: str = "") -> list[Conversation]:
        """Fetch sidebar summaries in one query instead of loading 50 messages per contact."""
        self.delete_expired_messages()
        rows = self._db.execute(
            """
            SELECT c.id, c.name, c.public_key, c.verify_key, c.last_seen, c.created_at, c.blocked,
                   m.id, m.contact_id, m.content, m.timestamp, m.direction, m.status, m.is_read,
                   COALESCE(u.unread_count, 0)
            FROM contacts c
            LEFT JOIN messages m ON m.id = (
                SELECT id FROM messages
                WHERE contact_id = c.id ORDER BY timestamp DESC LIMIT 1
            )
            LEFT JOIN (
                SELECT contact_id, COUNT(*) AS unread_count
                FROM messages
                WHERE direction = 'received' AND is_read = 0
                GROUP BY contact_id
            ) u ON u.contact_id = c.id
            WHERE ? = '' OR c.name LIKE ? OR EXISTS (
                SELECT 1 FROM messages search_messages
                WHERE search_messages.contact_id = c.id
                  AND search_messages.content LIKE ?
            )
            ORDER BY COALESCE(m.timestamp, 0) DESC
            """
            , (query, f"%{query}%", f"%{query}%")
        ).fetchall()
        conversations = []
        for row in rows:
            contact = self._row_to_contact(row[:7])
            latest = self._row_to_message(row[7:14]) if row[7] else None
            conversations.append(
                Conversation(
                    contact=contact,
                    messages=[latest] if latest else [],
                    unread_total=row[14],
                )
            )
        return conversations

    def save_draft(self, contact_id: str, content: str) -> None:
        self._db.execute(
            "INSERT INTO drafts(contact_id, content) VALUES (?, ?) "
            "ON CONFLICT(contact_id) DO UPDATE SET content=excluded.content",
            (contact_id, content),
        )
        self._db.commit()

    def get_draft(self, contact_id: str) -> str:
        row = self._db.execute(
            "SELECT content FROM drafts WHERE contact_id=?", (contact_id,)
        ).fetchone()
        return row[0] if row else ""

    def remember_relay(self, packet_id: str) -> bool:
        self._db.execute("DELETE FROM relay_seen WHERE seen_at < ?", (time.time() - 7 * 86400,))
        self._db.execute(
            "DELETE FROM relay_seen WHERE packet_id IN ("
            "SELECT packet_id FROM relay_seen ORDER BY seen_at DESC LIMIT -1 OFFSET 10000)"
        )
        cursor = self._db.execute(
            "INSERT OR IGNORE INTO relay_seen(packet_id, seen_at) VALUES (?, ?)",
            (packet_id, time.time()),
        )
        self._db.commit()
        return cursor.rowcount == 1

    def forget_relay(self, packet_id: str) -> None:
        self._db.execute("DELETE FROM relay_seen WHERE packet_id=?", (packet_id,))
        self._db.commit()

    def queue_relay(self, packet_id: str, envelope: bytes, via: str = "") -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO relay_queue(packet_id, envelope, via, created_at) "
            "VALUES (?, ?, ?, ?)",
            (packet_id, envelope, via, time.time()),
        )
        self._db.commit()

    def get_queued_relays(self) -> list[tuple[str, bytes, str]]:
        self._db.execute("DELETE FROM relay_queue WHERE created_at < ?", (time.time() - 7 * 86400,))
        self._db.execute(
            "DELETE FROM relay_queue WHERE packet_id IN ("
            "SELECT packet_id FROM relay_queue ORDER BY created_at DESC LIMIT -1 OFFSET 500)"
        )
        self._db.commit()
        return self._db.execute(
            "SELECT packet_id, envelope, via FROM relay_queue ORDER BY created_at"
        ).fetchall()

    def get_relay_queue_details(self) -> list[tuple[str, bytes, str, float]]:
        """Return relay packets and their last forwarding attempt for the dashboard."""
        self.get_queued_relays()
        return self._db.execute(
            "SELECT packet_id, envelope, via, created_at FROM relay_queue ORDER BY created_at"
        ).fetchall()

    def delete_queued_relay(self, packet_id: str) -> None:
        self._db.execute("DELETE FROM relay_queue WHERE packet_id=?", (packet_id,))
        self._db.commit()

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
            blocked=bool(row[6]),
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
