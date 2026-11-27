"""Unit tests for the storage module."""

import time
import pytest

from messenger.storage.database import DatabaseManager
from messenger.storage.models import (
    Contact,
    Message,
    MessageDirection,
    MessageStatus,
)


@pytest.fixture
def db(tmp_path):
    """Create a fresh database for each test."""
    db_path = tmp_path / "test.db"
    manager = DatabaseManager(db_path=db_path)
    assert manager.open("test_passphrase") is True
    yield manager
    manager.close()


class TestDatabaseContacts:
    """Tests for contact CRUD operations."""

    def test_save_and_get_contact(self, db):
        contact = Contact(name="Alice", public_key="a" * 64, verify_key="b" * 64)
        db.save_contact(contact)

        loaded = db.get_contact(contact.id)
        assert loaded is not None
        assert loaded.name == "Alice"
        assert loaded.public_key == "a" * 64

    def test_get_contact_by_public_key(self, db):
        contact = Contact(name="Bob", public_key="c" * 64, verify_key="d" * 64)
        db.save_contact(contact)

        loaded = db.get_contact_by_public_key("c" * 64)
        assert loaded is not None
        assert loaded.name == "Bob"

    def test_get_nonexistent_contact(self, db):
        assert db.get_contact("nonexistent") is None

    def test_get_all_contacts(self, db):
        for i in range(3):
            db.save_contact(
                Contact(
                    name=f"User {i}",
                    public_key=f"{i}" * 64,
                    verify_key=f"{i}" * 64,
                    last_seen=time.time() + i,
                )
            )

        contacts = db.get_all_contacts()
        assert len(contacts) == 3
        # Should be ordered by last_seen DESC
        assert contacts[0].name == "User 2"

    def test_update_contact(self, db):
        contact = Contact(name="Old Name", public_key="e" * 64, verify_key="f" * 64)
        db.save_contact(contact)

        contact.name = "New Name"
        db.save_contact(contact)

        loaded = db.get_contact(contact.id)
        assert loaded.name == "New Name"

    def test_delete_contact(self, db):
        contact = Contact(name="Deleteme", public_key="g" * 64, verify_key="h" * 64)
        db.save_contact(contact)
        db.delete_contact(contact.id)
        assert db.get_contact(contact.id) is None

    def test_block_contact_persists(self, db):
        contact = Contact(name="Blocked", public_key="i" * 64, verify_key="j" * 64)
        db.save_contact(contact)

        db.set_contact_blocked(contact.id, True)

        assert db.get_contact(contact.id).blocked is True


class TestDatabaseMessages:
    """Tests for message CRUD operations."""

    @pytest.fixture
    def contact(self, db):
        c = Contact(name="TestPeer", public_key="x" * 64, verify_key="y" * 64)
        db.save_contact(c)
        return c

    def test_save_and_get_messages(self, db, contact):
        msg = Message(
            contact_id=contact.id,
            content="Hello there!",
            direction=MessageDirection.SENT,
        )
        db.save_message(msg)

        messages = db.get_messages(contact.id)
        assert len(messages) == 1
        assert messages[0].content == "Hello there!"
        assert messages[0].direction == MessageDirection.SENT

    def test_messages_ordered_chronologically(self, db, contact):
        for i in range(5):
            db.save_message(
                Message(
                    contact_id=contact.id,
                    content=f"Message {i}",
                    timestamp=1000 + i,
                    direction=MessageDirection.SENT,
                )
            )

        messages = db.get_messages(contact.id)
        assert len(messages) == 5
        assert messages[0].content == "Message 0"
        assert messages[4].content == "Message 4"

    def test_mark_messages_read(self, db, contact):
        db.save_message(
            Message(
                contact_id=contact.id,
                content="Unread msg",
                direction=MessageDirection.RECEIVED,
                is_read=False,
            )
        )

        db.mark_messages_read(contact.id)
        messages = db.get_messages(contact.id)
        assert all(m.is_read for m in messages)

    def test_update_message_status(self, db, contact):
        msg = Message(
            contact_id=contact.id,
            content="Pending msg",
            direction=MessageDirection.SENT,
            status=MessageStatus.PENDING,
        )
        db.save_message(msg)

        db.update_message_status(msg.id, MessageStatus.DELIVERED)
        messages = db.get_messages(contact.id)
        assert messages[0].status == MessageStatus.DELIVERED

    def test_get_messages_with_limit(self, db, contact):
        for i in range(10):
            db.save_message(
                Message(
                    contact_id=contact.id,
                    content=f"Msg {i}",
                    timestamp=1000 + i,
                )
            )

        messages = db.get_messages(contact.id, limit=3)
        assert len(messages) == 3

    def test_message_expiry_removes_only_old_messages(self, db, contact):
        db.save_message(
            Message(contact_id=contact.id, content="old", timestamp=time.time() - 120)
        )
        db.save_message(Message(contact_id=contact.id, content="new", timestamp=time.time()))

        db.set_message_expiry(60)

        assert [message.content for message in db.get_messages(contact.id)] == ["new"]

    def test_settings_are_persisted(self, db):
        db.set_setting("language", "hi")

        assert db.get_setting("language") == "hi"

    def test_delete_contact_cascades_messages(self, db, contact):
        db.save_message(
            Message(contact_id=contact.id, content="Will be deleted")
        )
        db.delete_contact(contact.id)
        messages = db.get_messages(contact.id)
        assert len(messages) == 0


class TestDatabaseConversations:
    """Tests for conversation aggregation."""

    def test_get_conversations(self, db):
        c1 = Contact(
            name="Alice", public_key="1" * 64, verify_key="2" * 64, last_seen=100
        )
        c2 = Contact(
            name="Bob", public_key="3" * 64, verify_key="4" * 64, last_seen=200
        )
        db.save_contact(c1)
        db.save_contact(c2)

        db.save_message(
            Message(contact_id=c1.id, content="Hi Alice", timestamp=50)
        )
        db.save_message(
            Message(contact_id=c2.id, content="Hi Bob", timestamp=100)
        )

        convos = db.get_conversations()
        assert len(convos) == 2
        # Most recent message first
        assert convos[0].contact.name == "Bob"

    def test_conversation_unread_count(self, db):
        c = Contact(name="Peer", public_key="5" * 64, verify_key="6" * 64)
        db.save_contact(c)

        db.save_message(
            Message(
                contact_id=c.id,
                content="Unread 1",
                direction=MessageDirection.RECEIVED,
                is_read=False,
            )
        )
        db.save_message(
            Message(
                contact_id=c.id,
                content="Unread 2",
                direction=MessageDirection.RECEIVED,
                is_read=False,
            )
        )
        db.save_message(
            Message(
                contact_id=c.id,
                content="Sent msg",
                direction=MessageDirection.SENT,
            )
        )

        convos = db.get_conversations()
        assert convos[0].unread_count == 2


class TestDatabaseSecurity:
    """Tests for database encryption behavior."""

    def test_wrong_passphrase_fails_with_sqlcipher(self, tmp_path):
        """If SQLCipher is installed, a wrong passphrase should fail."""
        from messenger.storage.database import HAS_SQLCIPHER

        db_path = tmp_path / "encrypted.db"

        db1 = DatabaseManager(db_path=db_path)
        db1.open("correct_password")
        db1.save_contact(Contact(name="Test"))
        db1.close()

        db2 = DatabaseManager(db_path=db_path)
        if HAS_SQLCIPHER:
            assert db2.open("wrong_password") is False
        else:
            # Without SQLCipher, plain sqlite3 ignores the passphrase
            assert db2.open("wrong_password") is True
        db2.close()
