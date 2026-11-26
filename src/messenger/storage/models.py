"""
Data models for the messenger application.

All models are plain dataclasses — they are serialised to/from the
SQLCipher database by the DatabaseManager.
"""

from __future__ import annotations

import uuid
import time
from dataclasses import dataclass, field
from enum import Enum


class MessageDirection(Enum):
    """Whether a message was sent or received."""
    SENT = "sent"
    RECEIVED = "received"


class MessageStatus(Enum):
    """Delivery status of a message."""
    PENDING = "pending"      # Queued, not yet delivered
    DELIVERED = "delivered"  # Successfully delivered to peer
    FAILED = "failed"        # Delivery failed


@dataclass
class Contact:
    """A known peer / conversation partner."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    public_key: str = ""    # X25519 public key (hex)
    verify_key: str = ""    # Ed25519 verify key (hex)
    last_seen: float = 0.0  # Unix timestamp of last activity
    created_at: float = field(default_factory=time.time)

    @property
    def short_id(self) -> str:
        """First 8 chars of the public key for display."""
        return self.public_key[:8] if self.public_key else "unknown"


@dataclass
class Message:
    """A single chat message — stored encrypted in the database."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contact_id: str = ""
    content: str = ""
    timestamp: float = field(default_factory=time.time)
    direction: MessageDirection = MessageDirection.SENT
    status: MessageStatus = MessageStatus.PENDING
    is_read: bool = False

    @property
    def time_display(self) -> str:
        """Human-readable time (HH:MM)."""
        t = time.localtime(self.timestamp)
        return f"{t.tm_hour:02d}:{t.tm_min:02d}"

    @property
    def date_display(self) -> str:
        """Human-readable date (YYYY-MM-DD)."""
        t = time.localtime(self.timestamp)
        return f"{t.tm_year}-{t.tm_mon:02d}-{t.tm_mday:02d}"


@dataclass
class Conversation:
    """A conversation with a single contact (aggregation view)."""

    contact: Contact
    messages: list[Message] = field(default_factory=list)
    unread_total: int | None = None

    @property
    def unread_count(self) -> int:
        if self.unread_total is not None:
            return self.unread_total
        return sum(
            1
            for m in self.messages
            if m.direction == MessageDirection.RECEIVED and not m.is_read
        )

    @property
    def last_message(self) -> Message | None:
        return self.messages[-1] if self.messages else None

    @property
    def last_message_preview(self) -> str:
        msg = self.last_message
        if msg is None:
            return "No messages yet"
        preview = msg.content[:40]
        if len(msg.content) > 40:
            preview += "..."
        return preview
