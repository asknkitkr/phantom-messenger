"""
Phantom Messenger — Terminal UI Application.

Built with Textual for a rich, modern terminal interface that runs on
Windows, macOS, and Linux.

Screens:
    1. LoginScreen — passphrase entry to unlock the encrypted database & keys
    2. MainScreen  — sidebar with contacts + chat panel with messages
    3. ScanScreen  — BLE device discovery and key exchange
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message as TMessage
from textual.reactive import reactive, var
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
    TextArea,
)

from messenger.config import (
    DATA_DIR,
    MAX_CHUNK_PAYLOAD,
    MAX_MESSAGE_LENGTH,
    MIN_PASSPHRASE_LENGTH,
)
from messenger.crypto.keys import KeyManager
from messenger.crypto.encryption import MessageEncryptor
from messenger.storage.database import DatabaseManager
from messenger.storage.backup import decrypt_backup, encrypt_backup
from messenger.storage.models import (
    Contact,
    Conversation,
    Message as ChatMessage,
    MessageDirection,
    MessageStatus,
)
from messenger.transport.peripheral import (
    BaseTransport,
    BLEPeripheral,
    BLECentral,
)
from messenger.transport.protocol import (
    ChunkAssembler,
    MessageType,
    chunk_message,
    Chunk,
)
from messenger.transport.mesh import MAX_HOPS, RelayEnvelope

logger = logging.getLogger(__name__)

_TEXT = {
    "en": {
        "contacts": "  CONTACTS",
        "search": "Search contacts and messages",
        "connect": "Connect Nearby",
        "advertise": "Advertise",
        "keys": "My Keys",
        "tools": "Tools",
        "type_message": "Type a message...",
        "send": "Send",
        "select_contact": "  Select a contact",
    },
    "hi": {
        "contacts": "  संपर्क",
        "search": "संपर्क और संदेश खोजें",
        "connect": "पास के डिवाइस से जुड़ें",
        "advertise": "प्रसारण शुरू करें",
        "keys": "मेरी कुंजियां",
        "tools": "उपकरण",
        "type_message": "संदेश लिखें...",
        "send": "भेजें",
        "select_contact": "  संपर्क चुनें",
    },
    "es": {
        "contacts": "  CONTACTOS",
        "search": "Buscar contactos y mensajes",
        "connect": "Conectar cerca",
        "advertise": "Anunciar",
        "keys": "Mis claves",
        "tools": "Herramientas",
        "type_message": "Escribe un mensaje...",
        "send": "Enviar",
        "select_contact": "  Selecciona un contacto",
    },
}


# ======================================================================
# CSS Stylesheet
# ======================================================================

APP_CSS = """
Screen {
    background: $surface;
}

/* ---- Login Screen ---- */
#login-scroll {
    width: 100%;
    height: 100%;
    align: center top;
}

#login-container {
    width: 1fr;
    max-width: 60;
    height: auto;
    margin: 1 1;
    border: heavy $primary;
    padding: 1 2;
    background: $surface;
}

#login-title {
    text-align: center;
    text-style: bold;
    color: $text;
    margin-bottom: 1;
    width: 100%;
}

#login-subtitle {
    text-align: center;
    color: $text-muted;
    margin-bottom: 2;
    width: 100%;
}

#login-error {
    text-align: center;
    color: $error;
    margin-top: 1;
    width: 100%;
    display: none;
}

#passphrase-input {
    margin-bottom: 1;
}

.login-btn {
    width: 100%;
    margin-top: 1;
}

/* ---- Main Screen ---- */
#main-layout {
    layout: horizontal;
    height: 1fr;
}

#sidebar {
    width: 32;
    border-right: heavy $primary;
    height: 100%;
}

#sidebar-header {
    height: 3;
    padding: 0 1;
    background: $primary;
    color: $text;
    text-style: bold;
    content-align: center middle;
}

#contact-list {
    height: 1fr;
}

.compact .contact-item {
    padding: 0 1;
}

.contact-item {
    padding: 1 1;
    height: auto;
}

.contact-item:hover {
    background: $boost;
}

.contact-name {
    text-style: bold;
    color: $text;
}

.contact-preview {
    color: $text-muted;
}

/* ---- Right Panel (Chat + Logs) ---- */
#right-panel {
    width: 1fr;
    height: 100%;
}

#chat-panel {
    height: 1fr;
}

#chat-header {
    height: 3;
    padding: 0 2;
    background: $primary-darken-1;
    color: $text;
    text-style: bold;
    content-align: left middle;
}

#chat-messages {
    height: 1fr;
    padding: 1 2;
    background: $surface;
}

.empty-chat-placeholder {
    content-align: center middle;
    height: 100%;
    color: $text-muted;
}

.msg-row {
    margin-bottom: 1;
    width: 100%;
}

.msg-sent {
    text-align: right;
    color: $success;
}

.msg-received {
    text-align: left;
    color: $primary-lighten-2;
}

.msg-time {
    color: $text-muted;
}

#message-input-bar {
    height: 3;
    layout: horizontal;
    padding: 0 1;
    background: $surface;
    border-top: heavy $primary;
}

#message-input {
    width: 1fr;
}

#send-btn {
    width: 12;
    margin-left: 1;
}

/* ---- Scan Screen ---- */
#scan-container {
    width: 1fr;
    max-width: 70;
    height: auto;
    max-height: 90%;
    border: heavy $accent;
    margin: 1 1;
    padding: 1 2;
    background: $surface;
}

#scan-title {
    text-align: center;
    text-style: bold;
    margin-bottom: 1;
    width: 100%;
}

#scan-status {
    text-align: center;
    color: $text-muted;
    margin-bottom: 1;
    width: 100%;
}

#scan-results {
    height: auto;
    max-height: 15;
    margin-bottom: 1;
}

.scan-device {
    padding: 1;
}

.scan-btn-row {
    layout: horizontal;
    align: center middle;
    height: auto;
}

.scan-btn-row Button {
    margin: 0 1;
}

/* ---- Info Bar ---- */
#info-bar {
    dock: bottom;
    height: 1;
    background: $warning;
    color: $text;
    padding: 0 2;
}
"""


# ======================================================================
# Login Screen
# ======================================================================


class LoginScreen(Screen):
    """Passphrase entry to unlock the app."""

    def compose(self) -> ComposeResult:
        yield VerticalScroll(
            Container(
            Static("PHANTOM MESSENGER", id="login-title"),
            Static("Private messages without an internet connection", id="login-subtitle"),
            Input(
                placeholder="Enter your passphrase...",
                password=True,
                id="passphrase-input",
            ),
            Input(
                placeholder="Confirm your passphrase",
                password=True,
                id="confirm-passphrase-input",
            ),
            Static("", id="login-help"),
            Button("Unlock", variant="primary", classes="login-btn", id="unlock-btn"),
            Button(
                "Create Identity",
                variant="default",
                classes="login-btn",
                id="create-btn",
            ),
            Button("Create New Profile…", variant="error", id="new-profile-btn"),
            Static(
                "This permanently deletes the identity, contacts, and messages in this profile. "
                "You won't be able to recover them afterward. Type DELETE to continue.",
                id="reset-profile-help",
            ),
            Input(placeholder="Type DELETE to confirm", id="reset-profile-confirm-input"),
            Button("Delete profile and start over", variant="error", id="confirm-reset-btn"),
            Static("", id="login-error"),
            id="login-container",
            ),
            id="login-scroll",
        )

    def on_mount(self) -> None:
        has_identity = self.app.key_manager.has_keys()
        unlock = self.query_one("#unlock-btn", Button)
        create = self.query_one("#create-btn", Button)
        confirm = self.query_one("#confirm-passphrase-input", Input)
        reset_help = self.query_one("#reset-profile-help", Static)
        reset_input = self.query_one("#reset-profile-confirm-input", Input)
        reset_confirm = self.query_one("#confirm-reset-btn", Button)
        new_profile = self.query_one("#new-profile-btn", Button)
        confirm.styles.display = "none"
        reset_help.styles.display = "none"
        reset_input.styles.display = "none"
        reset_confirm.styles.display = "none"
        unlock.styles.display = "block" if has_identity else "none"
        create.styles.display = "none" if has_identity else "block"
        new_profile.styles.display = "block" if has_identity else "none"
        self.query_one("#login-help", Static).update(
            "Enter your passphrase to unlock your identity."
            if has_identity
            else "Choose a passphrase to create your identity."
        )
        self.query_one("#passphrase-input", Input).focus()

    @on(Button.Pressed, "#unlock-btn")
    def handle_unlock(self) -> None:
        passphrase = self.query_one("#passphrase-input", Input).value
        if not passphrase.strip():
            self._show_error("Passphrase cannot be empty.")
            return
        if not self.app.key_manager.has_keys():
            self._show_error("Create an identity first, then unlock it here.")
            return
        self.app.post_message(self.Unlock(passphrase))

    @on(Button.Pressed, "#create-btn")
    def handle_create(self) -> None:
        passphrase = self.query_one("#passphrase-input", Input).value
        if not passphrase.strip():
            self._show_error("Enter a passphrase to protect your identity.")
            return
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            self._show_error(f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters.")
            return
        confirm = self.query_one("#confirm-passphrase-input", Input)
        if confirm.styles.display == "none":
            confirm.styles.display = "block"
            self.query_one("#create-btn", Button).label = "Create Identity"
            self.query_one("#login-help", Static).update(
                "Enter your passphrase again to make sure it is correct."
            )
            confirm.focus()
            return
        if passphrase != confirm.value:
            self._show_error("The passphrases don't match. Please try again.")
            return
        self.app.post_message(self.CreateIdentity(passphrase))

    @on(Button.Pressed, "#new-profile-btn")
    def handle_reset_profile(self) -> None:
        self.query_one("#reset-profile-help", Static).styles.display = "block"
        self.query_one("#reset-profile-confirm-input", Input).styles.display = "block"
        self.query_one("#confirm-reset-btn", Button).styles.display = "block"

    @on(Button.Pressed, "#confirm-reset-btn")
    def handle_confirm_reset(self) -> None:
        confirmation = self.query_one("#reset-profile-confirm-input", Input).value
        if confirmation != "DELETE":
            self._show_error('Type DELETE to confirm removing this profile.')
            return
        self.app.post_message(self.ResetProfile())

    @on(Input.Submitted, "#passphrase-input")
    def handle_submit(self) -> None:
        passphrase = self.query_one("#passphrase-input", Input).value
        if not passphrase.strip():
            return
        if not self.app.key_manager.has_keys():
            self._show_error("Create an identity first, then unlock it here.")
            return
        self.app.post_message(self.Unlock(passphrase))

    def _show_error(self, msg: str) -> None:
        err = self.query_one("#login-error", Static)
        err.update(msg)
        err.styles.display = "block"

    # Custom messages
    class Unlock(TMessage):
        def __init__(self, passphrase: str) -> None:
            super().__init__()
            self.passphrase = passphrase

    class CreateIdentity(TMessage):
        def __init__(self, passphrase: str) -> None:
            super().__init__()
            self.passphrase = passphrase

    class ResetProfile(TMessage):
        """Delete the current identity and local profile data."""


class CreateProfileScreen(Screen):
    """Set a passphrase for a replacement profile after reset."""

    def compose(self) -> ComposeResult:
        yield VerticalScroll(
            Container(
            Static("CREATE NEW PROFILE", id="login-title"),
            Static("Choose a passphrase to protect your new identity.", id="login-subtitle"),
            Input(placeholder="New passphrase", password=True, id="new-passphrase-input"),
            Input(placeholder="Confirm passphrase", password=True, id="confirm-new-passphrase-input"),
            Static("", id="login-error"),
            Button("Create Profile", variant="primary", id="create-profile-btn"),
            id="login-container",
            ),
            id="login-scroll",
        )

    @on(Button.Pressed, "#create-profile-btn")
    def handle_create_profile(self) -> None:
        passphrase = self.query_one("#new-passphrase-input", Input).value
        confirmation = self.query_one("#confirm-new-passphrase-input", Input).value
        if not passphrase.strip():
            self._show_error("Enter a passphrase to protect your new identity.")
        elif len(passphrase) < MIN_PASSPHRASE_LENGTH:
            self._show_error(f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters.")
        elif passphrase != confirmation:
            self._show_error("The passphrases don't match. Please try again.")
        else:
            self.app.post_message(LoginScreen.CreateIdentity(passphrase))

    def on_mount(self) -> None:
        self.query_one("#new-passphrase-input", Input).focus()

    def _show_error(self, message: str) -> None:
        error = self.query_one("#login-error", Static)
        error.update(message)
        error.styles.display = "block"


class RenameContactScreen(Screen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, contact_id: str, current_name: str) -> None:
        super().__init__()
        self.contact_id = contact_id
        self.current_name = current_name

    def compose(self) -> ComposeResult:
        yield Container(
            Static("RENAME CONTACT", id="scan-title"),
            Input(value=self.current_name, placeholder="Contact name", id="contact-name-input"),
            Horizontal(
                Button("Save", variant="primary", id="save-contact-name-btn"),
                Button("Cancel", variant="default", id="cancel-contact-name-btn"),
                classes="scan-btn-row",
            ),
            id="scan-container",
        )

    @on(Button.Pressed, "#save-contact-name-btn")
    def save_name(self) -> None:
        name = self.query_one("#contact-name-input", Input).value.strip()
        if not name:
            self.app.notify("Enter a name for this contact.", severity="warning")
            return
        self.app.post_message(self.RenameContact(self.contact_id, name))
        self.dismiss()

    @on(Button.Pressed, "#cancel-contact-name-btn")
    def cancel(self) -> None:
        self.dismiss()

    class RenameContact(TMessage):
        def __init__(self, contact_id: str, name: str) -> None:
            super().__init__()
            self.contact_id = contact_id
            self.name = name


class VerifyPeerScreen(Screen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, bundle: dict[str, str], fingerprint: str) -> None:
        super().__init__()
        self.bundle = bundle
        self.fingerprint = fingerprint

    def compose(self) -> ComposeResult:
        yield Container(
            Static("VERIFY NEW CONTACT", id="scan-title"),
            Static(
                "Compare this code with your contact over a trusted channel. "
                "Only trust the contact if both codes match.",
                id="scan-status",
            ),
            Static(self.fingerprint, id="peer-fingerprint", markup=False),
            Horizontal(
                Button("Trust Contact", variant="primary", id="trust-contact-btn"),
                Button("Cancel", variant="default", id="cancel-trust-btn"),
                classes="scan-btn-row",
            ),
            id="scan-container",
        )

    @on(Button.Pressed, "#trust-contact-btn")
    def trust_contact(self) -> None:
        self.app.post_message(self.TrustPeer(self.bundle))
        self.dismiss()

    @on(Button.Pressed, "#cancel-trust-btn")
    def cancel(self) -> None:
        self.dismiss()

    class TrustPeer(TMessage):
        def __init__(self, bundle: dict[str, str]) -> None:
            super().__init__()
            self.bundle = bundle


class ConfirmRemoveContactScreen(Screen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, contact_id: str) -> None:
        super().__init__()
        self.contact_id = contact_id

    def compose(self) -> ComposeResult:
        yield Container(
            Static("REMOVE CONTACT?", id="scan-title"),
            Static("This also permanently deletes this contact's conversation.", id="scan-status"),
            Horizontal(
                Button("Delete Contact and Chat", variant="error", id="confirm-remove-contact-btn"),
                Button("Cancel", variant="default", id="cancel-remove-contact-btn"),
                classes="scan-btn-row",
            ),
            id="scan-container",
        )

    @on(Button.Pressed, "#confirm-remove-contact-btn")
    def confirm_remove(self) -> None:
        self.app.post_message(self.RemoveContact(self.contact_id))
        self.dismiss()

    @on(Button.Pressed, "#cancel-remove-contact-btn")
    def cancel(self) -> None:
        self.dismiss()

    class RemoveContact(TMessage):
        def __init__(self, contact_id: str) -> None:
            super().__init__()
            self.contact_id = contact_id


class BackupRestoreScreen(Screen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        yield VerticalScroll(
            Container(
                Static("ENCRYPTED PROFILE BACKUP", id="scan-title"),
                Static(
                    "Backups include your identity, contacts, messages, and drafts. "
                    "Choose a strong backup password and keep the file somewhere safe. "
                    "Restoring replaces this profile.",
                    id="scan-status",
                ),
                Input(value=str(Path.home() / "Documents" / "phantom-backup.pmb"), placeholder="Backup file path", id="backup-path"),
                Input(placeholder="Backup password (12+ characters)", password=True, id="backup-password"),
                Input(placeholder="New profile password for restore", password=True, id="restore-password"),
                Input(placeholder="Confirm new profile password", password=True, id="restore-password-confirm"),
                Input(placeholder="Type RESTORE to replace this profile", id="restore-confirm"),
                Static("", id="login-error"),
                Horizontal(
                    Button("Create Backup", variant="primary", id="create-backup-btn"),
                    Button("Restore Backup", variant="error", id="restore-backup-btn"),
                    Button("Close", variant="default", id="close-backup-btn"),
                    classes="scan-btn-row",
                ),
                id="login-container",
            ),
            id="login-scroll",
        )

    @on(Button.Pressed, "#create-backup-btn")
    def create_backup(self) -> None:
        path = self.query_one("#backup-path", Input).value.strip()
        password = self.query_one("#backup-password", Input).value
        if len(password) < MIN_PASSPHRASE_LENGTH or not path:
            self._show_error("Choose a file path and a backup password of at least 12 characters.")
            return
        self.app.post_message(self.BackupAction("create", path, password))

    @on(Button.Pressed, "#restore-backup-btn")
    def restore_backup(self) -> None:
        path = self.query_one("#backup-path", Input).value.strip()
        backup_password = self.query_one("#backup-password", Input).value
        new_password = self.query_one("#restore-password", Input).value
        confirmation = self.query_one("#restore-password-confirm", Input).value
        if self.query_one("#restore-confirm", Input).value != "RESTORE":
            self._show_error("Type RESTORE to confirm replacing this profile.")
        elif len(new_password) < MIN_PASSPHRASE_LENGTH:
            self._show_error("The new profile password must be at least 12 characters.")
        elif new_password != confirmation:
            self._show_error("The new profile passwords don't match.")
        elif not backup_password or not path:
            self._show_error("Enter the backup file path and its password.")
        else:
            self.app.post_message(self.BackupAction("restore", path, backup_password, new_password))

    @on(Button.Pressed, "#close-backup-btn")
    def close(self) -> None:
        self.dismiss()

    def _show_error(self, text: str) -> None:
        error = self.query_one("#login-error", Static)
        error.update(text)
        error.styles.display = "block"

    class BackupAction(TMessage):
        def __init__(self, action: str, path: str, backup_password: str, new_password: str = "") -> None:
            super().__init__()
            self.action = action
            self.path = path
            self.backup_password = backup_password
            self.new_password = new_password


class MessageExpiryScreen(Screen):
    """Choose how long messages remain on this device."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("MESSAGE EXPIRY", id="scan-title"),
            Static(
                "Expired messages are removed from this device the next time the app refreshes.",
                id="scan-status",
            ),
            Button("Never delete messages", classes="expiry-choice", id="expiry-0"),
            Button("Delete after 1 hour", classes="expiry-choice", id="expiry-3600"),
            Button("Delete after 1 day", classes="expiry-choice", id="expiry-86400"),
            Button("Delete after 7 days", classes="expiry-choice", id="expiry-604800"),
            Button("Close", variant="default", id="close-expiry-btn"),
            id="scan-container",
        )

    @on(Button.Pressed, ".expiry-choice")
    def choose_expiry(self, event: Button.Pressed) -> None:
        seconds = int(event.button.id.removeprefix("expiry-"))
        self.app.post_message(self.SetExpiry(seconds))
        self.dismiss()

    @on(Button.Pressed, "#close-expiry-btn")
    def close_expiry(self) -> None:
        self.dismiss()

    class SetExpiry(TMessage):
        def __init__(self, seconds: int) -> None:
            super().__init__()
            self.seconds = seconds


class PanicWipeScreen(Screen):
    """Require an explicit confirmation before deleting the active profile."""

    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("PANIC WIPE", id="scan-title"),
            Static(
                "This permanently removes this device's identity, contacts, messages, "
                "drafts, and relay queue, then closes the app.",
                id="scan-status",
            ),
            Input(placeholder="Type WIPE to confirm", id="panic-wipe-confirm"),
            Static("", id="login-error"),
            Horizontal(
                Button("Wipe This Device", variant="error", id="confirm-panic-wipe-btn"),
                Button("Cancel", variant="default", id="cancel-panic-wipe-btn"),
                classes="scan-btn-row",
            ),
            id="scan-container",
        )

    @on(Button.Pressed, "#confirm-panic-wipe-btn")
    def confirm_wipe(self) -> None:
        if self.query_one("#panic-wipe-confirm", Input).value != "WIPE":
            error = self.query_one("#login-error", Static)
            error.update("Type WIPE to confirm removing this profile.")
            error.styles.display = "block"
            return
        self.app.post_message(self.WipeProfile())

    @on(Button.Pressed, "#cancel-panic-wipe-btn")
    def cancel_wipe(self) -> None:
        self.dismiss()

    class WipeProfile(TMessage):
        pass


class EmergencyBroadcastScreen(Screen):
    """Compose one signed, encrypted alert for every unblocked contact."""

    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("EMERGENCY BROADCAST", id="scan-title"),
            Static(
                "This queues the same signed and encrypted alert for every unblocked contact.",
                id="scan-status",
            ),
            Input(placeholder="Emergency message", id="broadcast-message", max_length=MAX_MESSAGE_LENGTH),
            Static("", id="login-error"),
            Horizontal(
                Button("Send to Trusted Contacts", variant="error", id="send-broadcast-btn"),
                Button("Cancel", variant="default", id="cancel-broadcast-btn"),
                classes="scan-btn-row",
            ),
            id="scan-container",
        )

    @on(Button.Pressed, "#send-broadcast-btn")
    def send_broadcast(self) -> None:
        text = self.query_one("#broadcast-message", Input).value
        if not text.strip() or not MessageEncryptor.is_valid_text(text):
            error = self.query_one("#login-error", Static)
            error.update("Enter a supported plain-text emergency message.")
            error.styles.display = "block"
            return
        self.app.post_message(self.Broadcast(text))
        self.dismiss()

    @on(Button.Pressed, "#cancel-broadcast-btn")
    def cancel_broadcast(self) -> None:
        self.dismiss()

    class Broadcast(TMessage):
        def __init__(self, text: str) -> None:
            super().__init__()
            self.text = text


class RelayDashboardScreen(Screen):
    """Show packets this device is carrying for the mesh."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, entries: list[str]) -> None:
        super().__init__()
        self.entries = entries

    def compose(self) -> ComposeResult:
        lines = "\n\n".join(self.entries) if self.entries else "No messages are waiting for relay."
        yield VerticalScroll(
            Container(
                Static("RELAY DASHBOARD", id="scan-title"),
                Static(
                    "Relay devices carry encrypted packets but cannot read their contents.",
                    id="scan-status",
                ),
                Static(lines, markup=False),
                Button("Close", variant="primary", id="close-relay-dashboard-btn"),
                id="scan-container",
            ),
            id="login-scroll",
        )

    @on(Button.Pressed, "#close-relay-dashboard-btn")
    def close_dashboard(self) -> None:
        self.dismiss()


class LanguageScreen(Screen):
    """Select the primary terminal interface language."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("LANGUAGE", id="scan-title"),
            Static("The main chat screen updates immediately. Some detailed dialogs remain in English.", id="scan-status"),
            Button("English", classes="language-choice", id="language-en"),
            Button("हिन्दी", classes="language-choice", id="language-hi"),
            Button("Español", classes="language-choice", id="language-es"),
            Button("Close", variant="default", id="close-language-btn"),
            id="scan-container",
        )

    @on(Button.Pressed, ".language-choice")
    def choose_language(self, event: Button.Pressed) -> None:
        self.app.post_message(self.SetLanguage(event.button.id.removeprefix("language-")))
        self.dismiss()

    @on(Button.Pressed, "#close-language-btn")
    def close_language(self) -> None:
        self.dismiss()

    class SetLanguage(TMessage):
        def __init__(self, code: str) -> None:
            super().__init__()
            self.code = code


class KeyboardHelpScreen(Screen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("KEYBOARD SHORTCUTS", id="scan-title"),
            Static(
                "Ctrl+N   Scan for nearby devices\n"
                "Ctrl+A   Start advertising\n"
                "Ctrl+K   Show your key bundle\n"
                "Ctrl+M   Toggle compact mode\n"
                "Ctrl+H   Show this help\n"
                "Ctrl+Q   Quit\n"
                "Enter    Send a message\n"
                "Escape   Close the current screen",
                id="scan-status",
                markup=False,
            ),
            Button("Close", variant="primary", id="close-help-btn"),
            id="scan-container",
        )

    @on(Button.Pressed, "#close-help-btn")
    def close_help(self) -> None:
        self.dismiss()


class ToolsScreen(Screen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, contact_id: str | None, contact_blocked: bool = False) -> None:
        super().__init__()
        self.contact_id = contact_id
        self.contact_blocked = contact_blocked

    def compose(self) -> ComposeResult:
        yield VerticalScroll(
            Container(
                Static("TOOLS", id="scan-title"),
                Button("Rename Contact", id="tool-rename", disabled=not self.contact_id),
                Button("Retry Pending Messages", id="tool-retry", disabled=not self.contact_id),
                Button("Remove Contact and Chat", variant="error", id="tool-remove", disabled=not self.contact_id),
                Button(
                    "Unblock Contact" if self.contact_blocked else "Block Contact",
                    variant="default" if self.contact_blocked else "error",
                    id="tool-block",
                    disabled=not self.contact_id,
                ),
                Button("Message Expiry", id="tool-expiry"),
                Button("Relay Dashboard", id="tool-relay"),
                Button("Emergency Broadcast", variant="error", id="tool-broadcast"),
                Button("Language", id="tool-language"),
                Button("Export Conversation", id="tool-export", disabled=not self.contact_id),
                Button("Encrypted Backup / Restore", id="tool-backup"),
                Button("Panic Wipe", variant="error", id="tool-panic-wipe"),
                Button("Disconnect", id="tool-disconnect"),
                Button("Compact Mode", id="tool-compact"),
                Button("Keyboard Help", id="tool-help"),
                Button("Close", variant="default", id="tool-close"),
                id="scan-container",
            ),
            id="login-scroll",
        )

    @on(Button.Pressed, "#tool-rename")
    def rename(self) -> None:
        self._select("rename")

    @on(Button.Pressed, "#tool-retry")
    def retry(self) -> None:
        self._select("retry")

    @on(Button.Pressed, "#tool-remove")
    def remove_contact(self) -> None:
        self._select("remove")

    @on(Button.Pressed, "#tool-block")
    def block_contact(self) -> None:
        self._select("block")

    @on(Button.Pressed, "#tool-expiry")
    def message_expiry(self) -> None:
        self._select("expiry")

    @on(Button.Pressed, "#tool-relay")
    def relay_dashboard(self) -> None:
        self._select("relay")

    @on(Button.Pressed, "#tool-broadcast")
    def emergency_broadcast(self) -> None:
        self._select("broadcast")

    @on(Button.Pressed, "#tool-language")
    def language(self) -> None:
        self._select("language")

    @on(Button.Pressed, "#tool-export")
    def export(self) -> None:
        self._select("export")

    @on(Button.Pressed, "#tool-backup")
    def backup(self) -> None:
        self._select("backup")

    @on(Button.Pressed, "#tool-panic-wipe")
    def panic_wipe(self) -> None:
        self._select("panic-wipe")

    @on(Button.Pressed, "#tool-disconnect")
    def disconnect(self) -> None:
        self._select("disconnect")

    @on(Button.Pressed, "#tool-compact")
    def compact(self) -> None:
        self._select("compact")

    @on(Button.Pressed, "#tool-help")
    def help(self) -> None:
        self._select("help")

    @on(Button.Pressed, "#tool-close")
    def close(self) -> None:
        self.dismiss()

    def _select(self, action: str) -> None:
        self.app.post_message(MainScreen.ToolAction(action, self.contact_id))
        self.dismiss()


# ======================================================================
# Main Screen
# ======================================================================


class MainScreen(Screen):
    """Main interface with contact sidebar + chat panel."""

    BINDINGS = [
        Binding("ctrl+n", "scan", "Scan for Devices"),
        Binding("ctrl+a", "advertise", "Advertise"),
        Binding("ctrl+k", "show_keys", "My Keys"),
        Binding("ctrl+m", "toggle_compact", "Compact Mode"),
        Binding("ctrl+h", "show_help", "Help"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    selected_contact: var[Optional[str]] = var(None)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            "Not connected. Messages will wait on this device.",
            id="connection-status",
            markup=False,
        )
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield Static(self.app.t("contacts"), id="sidebar-header")
                yield Input(placeholder=self.app.t("search"), id="contact-search")
                yield ListView(id="contact-list")
                yield Button(self.app.t("connect"), variant="primary", id="add-contact-btn")
                yield Button(self.app.t("advertise"), variant="default", id="advertise-btn")
                yield Button(self.app.t("keys"), variant="default", id="show-keys-btn")
                yield Button(self.app.t("tools"), variant="default", id="tools-btn")
            with Vertical(id="right-panel"):
                with Vertical(id="chat-panel"):
                    yield Static(self.app.t("select_contact"), id="chat-header", markup=False)
                    yield Button("Load older messages", variant="default", id="load-older-btn")
                    yield ScrollableContainer(
                        Static(
                            "Select a contact to start chatting\n\n"
                            "Press Ctrl+N to scan for nearby devices",
                            classes="empty-chat-placeholder",
                            markup=False,
                        ),
                        id="chat-messages",
                    )
                    with Horizontal(id="message-input-bar"):
                        yield Input(
                            placeholder=self.app.t("type_message"),
                            id="message-input",
                            max_length=MAX_MESSAGE_LENGTH,
                        )
                        yield Button(self.app.t("send"), variant="primary", id="send-btn")
        yield Footer()

    def on_mount(self) -> None:
        """When MainScreen is fully mounted, ask the app to populate contacts."""
        self._visible_messages = []
        self._draft_timer = None
        self.query_one("#load-older-btn", Button).disabled = True
        self.apply_language()
        self.set_interval(60, self.app.expire_messages)
        self.app.post_message(self.RefreshRequest())

    def on_unmount(self) -> None:
        if self._draft_timer:
            self._draft_timer.stop()
        if self.selected_contact:
            self.app.db_manager.save_draft(
                self.selected_contact,
                self.query_one("#message-input", Input).value,
            )

    class RefreshRequest(TMessage):
        """Request the app to refresh the contact list."""
        pass

    @on(Button.Pressed, "#send-btn")
    @on(Input.Submitted, "#message-input")
    def handle_send(self) -> None:
        inp = self.query_one("#message-input", Input)
        text = inp.value

        logger.debug(
            "handle_send: has_text=%s, selected_contact=%r",
            bool(text),
            self.selected_contact,
        )

        if not text.strip():
            self.notify("Please type a message first.", severity="warning")
            return
        if self.selected_contact is None:
            self.notify("Please select a contact first.", severity="warning")
            return

        if not MessageEncryptor.is_valid_text(text):
            self.notify(
                "Please use plain text. Emoji and some special characters aren't supported.",
                severity="warning",
            )
            return

        self.app.post_message(self.SendMessage(self.selected_contact, text))
        inp.value = ""

    @on(Input.Changed, "#message-input")
    def save_message_draft(self, event: Input.Changed) -> None:
        if self.selected_contact:
            if self._draft_timer:
                self._draft_timer.stop()
            contact_id, content = self.selected_contact, event.value
            self._draft_timer = self.set_timer(
                0.5, lambda: self.app.db_manager.save_draft(contact_id, content)
            )

    @on(Button.Pressed, "#add-contact-btn")
    def handle_scan_btn(self) -> None:
        self.action_scan()

    def action_scan(self) -> None:
        self.app.push_screen(ScanScreen())

    @on(Input.Changed, "#contact-search")
    def handle_contact_search(self, event: Input.Changed) -> None:
        self.app._refresh_ui(event.value)

    @on(Button.Pressed, "#load-older-btn")
    def handle_load_older(self) -> None:
        if self.selected_contact and self._visible_messages:
            self.app.post_message(
                self.LoadOlder(self.selected_contact, self._visible_messages[0].timestamp)
            )

    @on(Button.Pressed, "#tools-btn")
    def handle_tools(self) -> None:
        contact = self.app.db_manager.get_contact(self.selected_contact) if self.selected_contact else None
        self.app.push_screen(ToolsScreen(self.selected_contact, bool(contact and contact.blocked)))

    @on(Button.Pressed, "#advertise-btn")
    def handle_advertise_btn(self) -> None:
        self.action_advertise()

    def action_advertise(self) -> None:
        self.app.post_message(self.StartAdvertise())

    class StartAdvertise(TMessage):
        pass

    class RetryPending(TMessage):
        def __init__(self, contact_id: str) -> None:
            super().__init__()
            self.contact_id = contact_id

    @on(Button.Pressed, "#show-keys-btn")
    def handle_show_keys_btn(self) -> None:
        self.action_show_keys()

    def action_show_keys(self) -> None:
        self.app.post_message(self.ShowKeys())

    def action_toggle_compact(self) -> None:
        self.toggle_class("compact")

    def action_show_help(self) -> None:
        self.app.push_screen(KeyboardHelpScreen())

    def apply_language(self) -> None:
        """Refresh the main screen labels after changing language."""
        self.query_one("#sidebar-header", Static).update(self.app.t("contacts"))
        self.query_one("#contact-search", Input).placeholder = self.app.t("search")
        self.query_one("#add-contact-btn", Button).label = self.app.t("connect")
        self.query_one("#advertise-btn", Button).label = self.app.t("advertise")
        self.query_one("#show-keys-btn", Button).label = self.app.t("keys")
        self.query_one("#tools-btn", Button).label = self.app.t("tools")
        self.query_one("#message-input", Input).placeholder = self.app.t("type_message")
        self.query_one("#send-btn", Button).label = self.app.t("send")
        if self.selected_contact is None:
            self.query_one("#chat-header", Static).update(self.app.t("select_contact"))

    class ShowKeys(TMessage):
        pass

    class Disconnect(TMessage):
        pass

    class ExportConversation(TMessage):
        def __init__(self, contact_id: str) -> None:
            super().__init__()
            self.contact_id = contact_id

    class ToolAction(TMessage):
        def __init__(self, action: str, contact_id: str | None) -> None:
            super().__init__()
            self.action = action
            self.contact_id = contact_id

    class LoadOlder(TMessage):
        def __init__(self, contact_id: str, before: float) -> None:
            super().__init__()
            self.contact_id = contact_id
            self.before = before

    @on(ListView.Selected, "#contact-list")
    def handle_contact_selected(self, event: ListView.Selected) -> None:
        if event.item is None:
            return
        # Look up the contact_id by the item's index in the ListView
        idx = event.list_view.index
        if idx is not None and idx in self._contact_index_map:
            raw_id = self._contact_index_map[idx]
            if self.selected_contact != raw_id:
                self.selected_contact = raw_id
                self.query_one("#message-input", Input).value = self.app.db_manager.get_draft(raw_id)
                logger.info(f"Contact selected: {self.selected_contact}")
                self.app.post_message(self.ContactSelected(self.selected_contact))

    # Maps ListView index → contact_id (avoids DuplicateIds with widget IDs)
    _contact_index_map: dict[int, str] = {}

    def refresh_contacts(
        self,
        conversations: list[Conversation],
        connected_contact_id: str | None = None,
        relay_counts: dict[str, int] | None = None,
    ) -> None:
        """Refresh the contact list sidebar."""
        lv = self.query_one("#contact-list", ListView)

        # Remember which contact is currently selected so we can re-select it
        old_selected = self.selected_contact

        lv.clear()
        self._contact_index_map = {}

        selection_index = None

        for idx, conv in enumerate(conversations):
            c = conv.contact
            unread = f" ({conv.unread_count})" if conv.unread_count else ""
            status = ""
            if c.blocked:
                status = " [blocked]"
            elif c.id == connected_contact_id:
                status = " [nearby]"
            elif relay_counts and relay_counts.get(c.verify_key):
                status = f" [relay: {relay_counts[c.verify_key]}]"
            name_text = f"{c.name or c.short_id}{unread}{status}"
            preview = conv.last_message_preview

            self._contact_index_map[idx] = c.id
            item = ListItem(
                Label(name_text, classes="contact-name", markup=False),
                Label(preview, classes="contact-preview", markup=False),
                classes="contact-item",
            )
            lv.append(item)

            if c.id == old_selected:
                selection_index = idx

        # Re-apply selection if possible
        if selection_index is not None:
            lv.index = selection_index

    def refresh_messages(self, contact: Contact, messages: list[ChatMessage]) -> None:
        """Refresh the chat panel with messages for the selected contact."""
        header = self.query_one("#chat-header", Static)
        title = contact.name or contact.short_id
        header.update(f"  {title}{' [blocked]' if contact.blocked else ''}")
        message_input = self.query_one("#message-input", Input)
        message_input.value = self.app.db_manager.get_draft(contact.id)
        message_input.disabled = contact.blocked
        message_input.placeholder = "Contact is blocked" if contact.blocked else self.app.t("type_message")
        self.query_one("#send-btn", Button).disabled = contact.blocked

        container = self.query_one("#chat-messages", ScrollableContainer)
        container.remove_children()
        self._visible_messages = list(messages)
        load_older = self.query_one("#load-older-btn", Button)
        load_older.disabled = len(messages) < 100

        if not messages:
            container.mount(
                Static("No messages yet. Say hello!", classes="empty-chat-placeholder")
            )
            return

        for msg in messages:
            direction_class = (
                "msg-sent" if msg.direction == MessageDirection.SENT else "msg-received"
            )
            prefix = "You" if msg.direction == MessageDirection.SENT else contact.name or contact.short_id
            delivery_status = ""
            if msg.direction == MessageDirection.SENT:
                if msg.status == MessageStatus.DELIVERED:
                    delivery_status = " (delivered)"
                elif msg.status == MessageStatus.FAILED:
                    delivery_status = " (not sent; will retry when connected)"
                else:
                    delivery_status = " (waiting to send)"
            elif msg.is_read:
                delivery_status = " (read on this device)"

            line = Static(
                f"[{msg.date_display} {msg.time_display}] {prefix}: {msg.content}{delivery_status}",
                classes=f"msg-row {direction_class}",
                markup=False,
            )
            container.mount(line)

        # Scroll to bottom
        container.scroll_end(animate=False)

    _visible_messages: list[ChatMessage] = []

    def clear_chat(self) -> None:
        self._visible_messages = []
        self.query_one("#chat-header", Static).update(self.app.t("select_contact"))
        self.query_one("#message-input", Input).disabled = False
        self.query_one("#message-input", Input).placeholder = self.app.t("type_message")
        self.query_one("#send-btn", Button).disabled = False
        self.query_one("#chat-messages", ScrollableContainer).remove_children()
        self.query_one("#chat-messages", ScrollableContainer).mount(
            Static("Select a contact to start chatting", classes="empty-chat-placeholder", markup=False)
        )
        self.query_one("#load-older-btn", Button).disabled = True

    # Custom messages
    class SendMessage(TMessage):
        def __init__(self, contact_id: str, text: str) -> None:
            super().__init__()
            self.contact_id = contact_id
            self.text = text

    class ContactSelected(TMessage):
        def __init__(self, contact_id: str) -> None:
            super().__init__()
            self.contact_id = contact_id


# ======================================================================
# Scan Screen
# ======================================================================


class ScanScreen(Screen):
    """BLE device discovery and key exchange initiation."""

    BINDINGS = [
        Binding("escape", "dismiss", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("DEVICE SCANNER", id="scan-title"),
            Static("Looking for nearby devices...", id="scan-status"),
            ListView(id="scan-results"),
            Horizontal(
                Button("Refresh", variant="primary", id="scan-refresh-btn"),
                Button("Add Manual", variant="default", id="scan-manual-btn"),
                Button("Back", variant="error", id="scan-back-btn"),
                classes="scan-btn-row",
            ),
            id="scan-container",
        )

    def on_mount(self) -> None:
        self.run_scan()

    @work(thread=False)
    async def run_scan(self) -> None:
        status = self.query_one("#scan-status", Static)
        results_list = self.query_one("#scan-results", ListView)
        results_list.clear()

        status.update("Scanning for nearby devices...")
        refresh_btn = self.query_one("#scan-refresh-btn", Button)
        refresh_btn.disabled = True
        refresh_btn.label = "Scanning..."
        try:
            central = BLECentral()
            devices = await central.scan(timeout=5.0)
            if devices:
                count = len(devices)
                status.update(f"Found {count} nearby {'device' if count == 1 else 'devices'}:")
                for dev in devices:
                    item = ListItem(
                        Label(
                            f"{dev['name']} ({dev['address']}) RSSI: {dev['rssi']}",
                            markup=False,
                        ),
                        id=f"device-{dev['address']}",
                        classes="scan-device",
                    )
                    results_list.append(item)
            else:
                status.update(
                    "No Phantom devices found nearby.\n"
                    "Make sure the other device is running and advertising."
                )
        except Exception as exc:
            logger.warning("BLE scan failed: %s", exc)
            status.update(
                "Couldn't scan for devices. Check that Bluetooth is on and the app "
                "has permission, then try again or add a contact manually."
            )
        finally:
            try:
                refresh_btn = self.query_one("#scan-refresh-btn", Button)
                refresh_btn.disabled = False
                refresh_btn.label = "Refresh"
            except NoMatches:
                pass

    @on(Button.Pressed, "#scan-refresh-btn")
    def handle_refresh(self) -> None:
        self.run_scan()

    @on(Button.Pressed, "#scan-manual-btn")
    def handle_manual(self) -> None:
        self.app.push_screen(ManualAddScreen())

    @on(Button.Pressed, "#scan-back-btn")
    def handle_back(self) -> None:
        self.dismiss()

    @on(ListView.Selected, "#scan-results")
    def handle_device_selected(self, event: ListView.Selected) -> None:
        device_id = event.item.id
        if device_id:
            address = device_id.replace("device-", "")
            self.app.post_message(self.DeviceSelected(address))
            self.dismiss()

    class DeviceSelected(TMessage):
        def __init__(self, address: str) -> None:
            super().__init__()
            self.address = address


# ======================================================================
# Manual Add Screen
# ======================================================================


class KeyBundleScreen(Screen):
    """Show the public keys together as a copyable JSON bundle."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, bundle: str) -> None:
        super().__init__()
        self.bundle = bundle

    def compose(self) -> ComposeResult:
        yield Container(
            Static("Share this key bundle with your contact:", id="scan-title"),
            TextArea(self.bundle, read_only=True, id="key-bundle-view"),
            Static("If copying doesn't work in your terminal, select the text and copy it manually."),
            Horizontal(
                Button("Copy", variant="primary", id="copy-key-bundle-btn"),
                Button("Close", variant="default", id="close-key-bundle-btn"),
                classes="scan-btn-row",
            ),
            id="scan-container",
        )

    @on(Button.Pressed, "#copy-key-bundle-btn")
    def handle_copy(self) -> None:
        try:
            self.app.copy_to_clipboard(self.bundle)
        except Exception:
            self.app.notify(
                "Clipboard access isn't available. Select and copy the bundle instead.",
                severity="warning",
            )
        else:
            self.app.notify("Key bundle copied.", severity="information")

    @on(Button.Pressed, "#close-key-bundle-btn")
    def handle_close(self) -> None:
        self.dismiss()


class ManualAddScreen(Screen):
    """Manually add a contact by pasting their public key bundle."""

    BINDINGS = [
        Binding("escape", "dismiss", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("ADD CONTACT MANUALLY", id="scan-title"),
            Static(
                "Paste the JSON key bundle from your contact's My Keys screen:",
                id="scan-status",
            ),
            Input(placeholder="Contact name", id="manual-name"),
            Input(placeholder='{"public_key":"...","verify_key":"..."}', id="manual-bundle"),
            Horizontal(
                Button("Add", variant="primary", id="manual-add-btn"),
                Button("Cancel", variant="error", id="manual-cancel-btn"),
                classes="scan-btn-row",
            ),
            Static("", id="login-error"),
            id="scan-container",
        )

    @on(Button.Pressed, "#manual-add-btn")
    def handle_add(self) -> None:
        name = self.query_one("#manual-name", Input).value.strip()
        raw_bundle = self.query_one("#manual-bundle", Input).value.strip()
        try:
            bundle = json.loads(raw_bundle)
        except json.JSONDecodeError:
            bundle = None
        if not KeyManager.verify_peer_bundle(bundle):
            err = self.query_one("#login-error", Static)
            err.update("That key bundle isn't valid. Ask your contact to copy it again.")
            err.styles.display = "block"
            return

        public_key = bundle["public_key"].lower()
        verify_key = bundle["verify_key"].lower()
        if not name:
            name = public_key[:8]

        self.app.post_message(
            self.ManualContactAdd(name=name, public_key=public_key, verify_key=verify_key)
        )
        self.dismiss()

    @on(Button.Pressed, "#manual-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss()

    class ManualContactAdd(TMessage):
        def __init__(self, name: str, public_key: str, verify_key: str) -> None:
            super().__init__()
            self.name = name
            self.public_key = public_key
            self.verify_key = verify_key


# ======================================================================
# Main Application
# ======================================================================



class PhantomApp(App):
    """Phantom Messenger — the main Textual application."""

    TITLE = "Phantom Messenger"
    SUB_TITLE = "Private messages without an internet connection"
    CSS = APP_CSS

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(
        self,
        key_manager: KeyManager,
        db_manager: DatabaseManager,
        transport: BaseTransport | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.language = "en"
        self.key_manager = key_manager
        self.db_manager = db_manager
        self.transport = transport
        self._assembler = ChunkAssembler()
        self._connection_status_text = "Disconnected. Pending messages will send when reconnected."
        self._encryptors: dict[str, MessageEncryptor] = {}
        self._pending_deliveries: dict[bytes, ChatMessage] = {}
        self._sending_message_ids: set[str] = set()
        self._connected_contact_id: str | None = None

    def t(self, key: str) -> str:
        """Return a translated primary-interface label."""
        return _TEXT.get(self.language, _TEXT["en"]).get(key, _TEXT["en"].get(key, key))

    def _load_language(self) -> None:
        language = self.db_manager.get_setting("language", "en")
        self.language = language if language in _TEXT else "en"


    def on_unmount(self) -> None:
        if self.transport:
            asyncio.create_task(self.transport.stop())

    def on_mount(self) -> None:
        self.push_screen(LoginScreen())

    # ------------------------------------------------------------------
    # Login Handlers
    # ------------------------------------------------------------------

    @on(LoginScreen.ResetProfile)
    def handle_reset_profile(self) -> None:
        try:
            self.db_manager.reset()
            self.key_manager.reset()
        except OSError as exc:
            logger.error("Failed to reset profile: %s", exc)
            self.notify("Could not delete the profile. Check file permissions and try again.", severity="error")
            return
        self.notify("Profile deleted. Create a new identity to continue.", severity="information")
        if isinstance(self.screen, LoginScreen):
            self.switch_screen(CreateProfileScreen())

    @on(PanicWipeScreen.WipeProfile)
    @work(thread=False)
    async def handle_panic_wipe(self) -> None:
        if self.transport:
            await self.transport.stop()
        self._pending_deliveries.clear()
        self._sending_message_ids.clear()
        self._encryptors.clear()
        self.db_manager.reset()
        self.key_manager.reset()
        self.exit(message="Profile removed. Restart Phantom Messenger to create a new profile.")

    @on(VerifyPeerScreen.TrustPeer)
    @work(thread=False)
    async def handle_trust_peer(self, message: VerifyPeerScreen.TrustPeer) -> None:
        await self._accept_peer_bundle(message.bundle)

    @on(BackupRestoreScreen.BackupAction)
    @work(thread=False)
    async def handle_backup_action(self, message: BackupRestoreScreen.BackupAction) -> None:
        path = Path(message.path).expanduser()
        try:
            if message.action == "create":
                snapshot = {
                    "version": 1,
                    "keys": self.key_manager.export_private_bundle(),
                    **self.db_manager.export_profile_data(),
                }
                blob = encrypt_backup(snapshot, message.backup_password)
                path.parent.mkdir(parents=True, exist_ok=True)
                temporary = path.with_suffix(path.suffix + ".tmp")
                temporary.write_bytes(blob)
                if os.name != "nt":
                    temporary.chmod(0o600)
                temporary.replace(path)
                self.notify(f"Encrypted backup saved to {path}", severity="information")
            else:
                snapshot = decrypt_backup(path.read_bytes(), message.backup_password)
                if snapshot.get("version") != 1 or not all(
                    isinstance(snapshot.get(key), list) for key in ("contacts", "messages", "drafts")
                ):
                    raise ValueError("Backup contents are incomplete")
                key_bundle = snapshot.get("keys")
                if not isinstance(key_bundle, dict) or set(("signing_key", "private_key")) - key_bundle.keys():
                    raise ValueError("Backup does not contain an identity")
                self.db_manager.restore_profile_data(snapshot)
                self.db_manager.rekey(message.new_password)
                self.key_manager.restore_private_bundle(key_bundle, message.new_password)
                self._load_language()
                self._encryptors.clear()
                self._pending_deliveries.clear()
                self._sending_message_ids.clear()
                if self.transport and self.transport.is_connected():
                    await self.transport.stop()
                self._refresh_ui("")
                current = next((screen for screen in self.screen_stack if isinstance(screen, MainScreen)), None)
                if current and current.selected_contact:
                    self._refresh_chat(current.selected_contact)
                self.notify("Profile restored. Your new profile password is now active.", severity="information")
        except Exception as exc:
            logger.error("Profile backup operation failed: %s", exc)
            self.notify(f"Backup could not be completed: {exc}", severity="error")

    @on(LoginScreen.Unlock)
    def handle_unlock(self, message: LoginScreen.Unlock) -> None:
        passphrase = message.passphrase

        if not self.key_manager.has_keys():
            self.notify(
                "No identity found. Create one to get started.",
                severity="warning",
            )
            return

        # Load keys
        if not self.key_manager.load(passphrase):
            self.notify("Wrong passphrase. Try again.", severity="error")
            return

        # Open database
        if not self.db_manager.open(passphrase):
            self.notify(
                f"Failed to open database: check {DATA_DIR / 'phantom.log'}",
                severity="error",
            )
            return

        self._load_language()

        self._enter_main()

    @on(LoginScreen.CreateIdentity)
    def handle_create_identity(self, message: LoginScreen.CreateIdentity) -> None:
        passphrase = message.passphrase

        if self.key_manager.has_keys():
            self.notify("An identity already exists. Unlock it to continue.", severity="warning")
            return

        if not self.db_manager.open(passphrase):
            self.notify(
                f"Failed to create database: check {DATA_DIR / 'phantom.log'}",
                severity="error",
            )
            return

        self._load_language()

        self.key_manager.generate()
        self.key_manager.save(passphrase)

        if not self.key_manager.load(passphrase):
            self.notify("Failed to load newly created keys.", severity="error")
            return

        self.notify(
            f"Identity created! Your public key:\n{self.key_manager.public_key_hex[:16]}...",
            severity="information",
        )
        self._enter_main()

    def _enter_main(self) -> None:
        """Switch to the main screen and start BLE transport."""
        self.pop_screen()  # Remove login screen
        main = MainScreen()
        self.push_screen(main)
        # NOTE: Do NOT call _refresh_ui() here — MainScreen is not yet mounted.
        # MainScreen.on_mount() will post RefreshRequest which triggers the refresh.

        # Start BLE transport if available
        if self.transport:
            self._start_transport()

    # ------------------------------------------------------------------
    # Main Screen Handlers
    # ------------------------------------------------------------------

    @on(MainScreen.RefreshRequest)
    def handle_refresh_request(self, message: MainScreen.RefreshRequest) -> None:
        """MainScreen has mounted — now safe to populate the contact list."""
        logger.info("MainScreen mounted, refreshing contacts...")
        self._refresh_ui()
        if self.transport and self.transport.is_connected():
            self._set_connection_status("Connected to a nearby device.")
        elif isinstance(self.transport, BLEPeripheral) and self.transport.is_advertising():
            self._set_connection_status("Advertising and waiting for a device.")
        else:
            self._set_connection_status("Disconnected. Pending messages will send when reconnected.")

    def expire_messages(self) -> None:
        """Periodically remove messages that passed the selected expiry period."""
        if not self.db_manager.delete_expired_messages():
            return
        self._refresh_ui()
        current = next((screen for screen in self.screen_stack if isinstance(screen, MainScreen)), None)
        if current and current.selected_contact:
            self._refresh_chat(current.selected_contact)

    @on(MainScreen.ContactSelected)
    def handle_contact_selected(self, message: MainScreen.ContactSelected) -> None:
        contact = self.db_manager.get_contact(message.contact_id)
        if contact is None:
            return

        self.db_manager.mark_messages_read(contact.id)
        messages = self.db_manager.get_messages(contact.id)
        self._refresh_ui()

        current = self.screen
        if isinstance(current, MainScreen):
            current.refresh_messages(contact, messages)

    @on(RenameContactScreen.RenameContact)
    def handle_rename_contact(self, message: RenameContactScreen.RenameContact) -> None:
        contact = self.db_manager.get_contact(message.contact_id)
        if contact:
            contact.name = message.name
            self.db_manager.save_contact(contact)
            self._refresh_ui()
            self._refresh_chat(contact.id)

    @on(MainScreen.ToolAction)
    def handle_tool_action(self, message: MainScreen.ToolAction) -> None:
        contact_id = message.contact_id
        if message.action == "rename" and contact_id:
            contact = self.db_manager.get_contact(contact_id)
            if contact:
                self.push_screen(RenameContactScreen(contact.id, contact.name))
        elif message.action == "retry" and contact_id:
            self._retry_pending_messages(contact_id)
        elif message.action == "remove" and contact_id:
            self.push_screen(ConfirmRemoveContactScreen(contact_id))
        elif message.action == "block" and contact_id:
            contact = self.db_manager.get_contact(contact_id)
            if contact:
                self.db_manager.set_contact_blocked(contact_id, not contact.blocked)
                state = "unblocked" if contact.blocked else "blocked"
                self.notify(f"{contact.name or contact.short_id} is now {state}.", severity="information")
                self._refresh_ui()
                self._refresh_chat(contact_id)
        elif message.action == "expiry":
            self.push_screen(MessageExpiryScreen())
        elif message.action == "relay":
            self.push_screen(RelayDashboardScreen(self._relay_dashboard_entries()))
        elif message.action == "broadcast":
            self.push_screen(EmergencyBroadcastScreen())
        elif message.action == "language":
            self.push_screen(LanguageScreen())
        elif message.action == "panic-wipe":
            self.push_screen(PanicWipeScreen())
        elif message.action == "export" and contact_id:
            self.handle_export_conversation(MainScreen.ExportConversation(contact_id))
        elif message.action == "backup":
            self.push_screen(BackupRestoreScreen())
        elif message.action == "disconnect":
            self.handle_disconnect()
        elif message.action == "compact":
            main = next((screen for screen in self.screen_stack if isinstance(screen, MainScreen)), None)
            if main:
                main.action_toggle_compact()
        elif message.action == "help":
            self.push_screen(KeyboardHelpScreen())

    @on(MessageExpiryScreen.SetExpiry)
    def handle_message_expiry(self, message: MessageExpiryScreen.SetExpiry) -> None:
        self.db_manager.set_message_expiry(message.seconds)
        label = "never" if message.seconds == 0 else f"after {message.seconds // 3600} hour(s)"
        self.notify(f"Messages will expire {label}.", severity="information")
        self._refresh_ui()
        current = next((screen for screen in self.screen_stack if isinstance(screen, MainScreen)), None)
        if current and current.selected_contact:
            self._refresh_chat(current.selected_contact)

    @on(LanguageScreen.SetLanguage)
    def handle_language(self, message: LanguageScreen.SetLanguage) -> None:
        if message.code not in _TEXT:
            return
        self.language = message.code
        self.db_manager.set_setting("language", message.code)
        current = next((screen for screen in self.screen_stack if isinstance(screen, MainScreen)), None)
        if current:
            current.apply_language()

    @on(EmergencyBroadcastScreen.Broadcast)
    def handle_emergency_broadcast(self, message: EmergencyBroadcastScreen.Broadcast) -> None:
        contacts = [contact for contact in self.db_manager.get_all_contacts() if not contact.blocked]
        if not contacts:
            self.notify("There are no unblocked contacts to receive this broadcast.", severity="warning")
            return
        for contact in contacts:
            chat_message = ChatMessage(
                contact_id=contact.id,
                content=message.text,
                direction=MessageDirection.SENT,
                status=MessageStatus.PENDING,
            )
            self.db_manager.save_message(chat_message)
            if self.transport and self.transport.is_connected():
                self._send_encrypted(contact, chat_message)
        self._set_connection_status(self._connection_status_text)
        self._refresh_ui()
        self.notify(f"Emergency broadcast queued for {len(contacts)} contact(s).", severity="information")

    @on(MainScreen.RetryPending)
    def handle_retry_pending(self, message: MainScreen.RetryPending) -> None:
        self._retry_pending_messages(message.contact_id)

    @work(thread=False)
    async def _retry_pending_messages(self, contact_id: str) -> None:
        if not self.transport or not self.transport.is_connected():
            self.notify("Connect to this contact before retrying queued messages.", severity="warning")
            return
        contact = self.db_manager.get_contact(contact_id)
        if not contact or contact.blocked:
            return
        pending = self.db_manager.get_undelivered_messages(contact_id)
        awaiting_ack = {item.id for item in self._pending_deliveries.values()}
        pending = [item for item in pending if item.id not in awaiting_ack]
        for message in pending:
            if not self.transport.is_connected():
                break
            message.status = MessageStatus.PENDING
            self.db_manager.update_message_status(message.id, message.status)
            await self._transmit_message(contact, message)
        if pending:
            self.notify(f"Retried {len(pending)} pending message(s).", severity="information")
        else:
            self.notify("There are no pending messages for this contact.", severity="information")

    @on(ConfirmRemoveContactScreen.RemoveContact)
    def handle_remove_contact(self, message: ConfirmRemoveContactScreen.RemoveContact) -> None:
        self.db_manager.delete_contact(message.contact_id)
        current = next((screen for screen in self.screen_stack if isinstance(screen, MainScreen)), None)
        if current and current.selected_contact == message.contact_id:
            current.selected_contact = None
            current.clear_chat()
        self._refresh_ui()

    @on(MainScreen.ExportConversation)
    def handle_export_conversation(self, message: MainScreen.ExportConversation) -> None:
        contact = self.db_manager.get_contact(message.contact_id)
        if not contact:
            return
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in (contact.name or contact.short_id))
        export_path = Path.home() / "Documents" / f"Phantom-{safe_name}.txt"
        export_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"Conversation with {contact.name or contact.short_id}", ""]
        for item in self.db_manager.get_messages(contact.id, limit=100000):
            speaker = "You" if item.direction == MessageDirection.SENT else contact.name or contact.short_id
            lines.append(f"[{item.date_display} {item.time_display}] {speaker}: {item.content}")
        export_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.notify(f"Conversation exported to {export_path}", severity="information")

    @on(MainScreen.LoadOlder)
    def handle_load_older(self, message: MainScreen.LoadOlder) -> None:
        contact = self.db_manager.get_contact(message.contact_id)
        current = next((screen for screen in self.screen_stack if isinstance(screen, MainScreen)), None)
        if not contact or not current:
            return
        older = self.db_manager.get_messages(contact.id, before=message.before)
        if not older:
            current.query_one("#load-older-btn", Button).disabled = True
            return
        current.refresh_messages(contact, older + current._visible_messages)
        current.query_one("#load-older-btn", Button).disabled = len(older) < 100
        self.call_later(lambda: current.query_one("#chat-messages", ScrollableContainer).scroll_home(animate=False))

    @on(MainScreen.Disconnect)
    @work(thread=False)
    async def handle_disconnect(self) -> None:
        if self.transport:
            await self.transport.stop()
        self._set_connection_status("Disconnected. Pending messages will send when reconnected.")

    @on(MainScreen.SendMessage)
    def handle_send_message(self, message: MainScreen.SendMessage) -> None:
        contact = self.db_manager.get_contact(message.contact_id)
        if contact is None:
            return
        if contact.blocked:
            self.notify("Unblock this contact before sending a message.", severity="warning")
            return

        # Create message record
        chat_msg = ChatMessage(
            contact_id=contact.id,
            content=message.text,
            direction=MessageDirection.SENT,
            status=MessageStatus.PENDING,
        )
        self.db_manager.save_message(chat_msg)
        self._set_connection_status(self._connection_status_text)

        # Refresh UI immediately so the message appears
        self._refresh_chat(contact.id)

        # Encrypt and send via BLE (if connected)
        if self.transport and self.transport.is_connected():
            self._send_encrypted(contact, chat_msg)
        else:
            self.notify(
                "Saved on this device. It will send when you reconnect to this contact.",
                severity="information",
            )

    @work(thread=False)
    async def _send_encrypted(self, contact: Contact, chat_msg: ChatMessage) -> None:
        """Queue delivery work without blocking the UI."""
        await self._transmit_message(contact, chat_msg)

    async def _transmit_message(self, contact: Contact, chat_msg: ChatMessage) -> None:
        """Encrypt and send one saved message, leaving it retryable on failure."""
        if chat_msg.id in self._sending_message_ids:
            return
        self._sending_message_ids.add(chat_msg.id)
        delivery_id: bytes | None = None
        try:
            encryptor = self._get_encryptor(contact)
            encrypted = encryptor.encrypt(chat_msg.content)
            if self.transport and self.transport.is_connected():
                delivery_id = hashlib.sha256(chat_msg.id.encode("utf-8")).digest()
                relay = RelayEnvelope.create(
                    "message",
                    self.key_manager.identity_hex,
                    contact.verify_key,
                    encrypted,
                    packet_id=delivery_id.hex(),
                )
                self.db_manager.remember_relay(relay.packet_id)
                self.db_manager.queue_relay(
                    relay.packet_id,
                    relay.encode(),
                    self._connected_peer_public_key(),
                )
                chunks = self._chunk_message(MessageType.RELAY_MESSAGE, relay.encode())
                self._pending_deliveries[delivery_id] = chat_msg
                for chunk in chunks:
                    await self.transport.send(chunk.to_bytes())
            else:
                chat_msg.status = MessageStatus.PENDING

        except Exception as exc:
            if delivery_id is not None:
                self._pending_deliveries.pop(delivery_id, None)
            logger.warning("Message delivery attempt failed: %s", exc)
            if chat_msg.status != MessageStatus.DELIVERED:
                chat_msg.status = MessageStatus.FAILED
        finally:
            self._sending_message_ids.discard(chat_msg.id)
            self.db_manager.update_message_status(chat_msg.id, chat_msg.status)
            self._set_connection_status(self._connection_status_text)
            self._refresh_chat(contact.id)

    # ------------------------------------------------------------------
    # Manual Contact Add
    # ------------------------------------------------------------------

    @on(ManualAddScreen.ManualContactAdd)
    def handle_manual_add(self, message: ManualAddScreen.ManualContactAdd) -> None:
        existing = self.db_manager.get_contact_by_public_key(message.public_key)
        if existing:
            if existing.verify_key != message.verify_key:
                self.notify(
                    "That encryption key is already saved with a different identity key.",
                    severity="error",
                )
            else:
                self.notify("This contact is already in your list.", severity="warning")
            return

        contact = Contact(
            name=message.name,
            public_key=message.public_key,
            verify_key=message.verify_key,
            last_seen=time.time(),
        )
        self.db_manager.save_contact(contact)
        self.notify(f"Contact '{contact.name}' added!", severity="information")
        self._refresh_ui()

    # ------------------------------------------------------------------
    # BLE Device Connection
    # ------------------------------------------------------------------

    @on(ScanScreen.DeviceSelected)
    def handle_device_selected(self, message: ScanScreen.DeviceSelected) -> None:
        self._connect_to_peer(message.address)

    @work(thread=False)
    async def _connect_to_peer(self, address: str) -> None:
        """Connect to another device and exchange keys."""
        logger.info(f"Connecting to {address}...")
        central = BLECentral()
        central.set_callbacks(
            on_data=self._on_data_received,
            on_connect=self._on_peer_connected,
            on_disconnect=self._on_peer_disconnected,
        )

        if await central.connect_to(address):
            self.transport = central

            try:
                # Send our key bundle
                bundle = json.dumps(self.key_manager.get_public_bundle()).encode()
                chunks = self._chunk_message(MessageType.KEY_EXCHANGE, bundle)
                for chunk in chunks:
                    await central.send(chunk.to_bytes())

                logger.info("Connected and key exchange sent!")
            except Exception as exc:
                logger.error("Failed to send key bundle: %s", exc)
        else:
            logger.error(f"Failed to connect to {address}.")
            self._set_connection_status(
                "Couldn't connect. Check that the other device is nearby and advertising."
            )
            self.notify(
                "Couldn't connect to that device. Check Bluetooth and try again.",
                severity="error",
            )

    # ------------------------------------------------------------------
    # Incoming Data
    # ------------------------------------------------------------------

    async def _on_data_received(self, data: bytes) -> None:
        """Handle raw data received from BLE transport."""
        try:
            chunk = Chunk.from_bytes(data)
            result = self._assembler.feed(chunk)
            if result is not None:
                msg_type, payload = result
                logger.debug(f"Message assembled: type={msg_type}, {len(payload)}b")
                await self._handle_complete_message(msg_type, payload)
        except Exception as exc:
            logger.error("Error processing incoming data: %s", exc, exc_info=True)

    async def _handle_complete_message(
        self, msg_type: MessageType, payload: bytes
    ) -> None:
        """Process a fully reassembled message."""
        if msg_type == MessageType.KEY_EXCHANGE:
            await self._handle_key_exchange(payload)
        elif msg_type == MessageType.TEXT_MESSAGE:
            await self._handle_text_message(payload)
        elif msg_type == MessageType.ACK:
            self._handle_ack_payload(payload)
        elif msg_type == MessageType.RELAY_MESSAGE:
            await self._handle_relay_packet(payload)

    def _handle_ack_payload(self, payload: bytes) -> None:
        if len(payload) != 96:
            return
        delivery_id, signature = payload[:32], payload[32:]
        message = self._pending_deliveries.get(delivery_id)
        contact = self.db_manager.get_contact(message.contact_id) if message else None
        if contact is None or contact.blocked:
            return
        try:
            from nacl.encoding import HexEncoder
            from nacl.signing import VerifyKey

            VerifyKey(contact.verify_key.encode(), encoder=HexEncoder).verify(delivery_id, signature)
        except Exception:
            logger.warning("Ignoring an invalid delivery acknowledgement.")
            return
        self._pending_deliveries.pop(delivery_id, None)
        self.db_manager.delete_queued_relay(delivery_id.hex())
        message.status = MessageStatus.DELIVERED
        self.db_manager.update_message_status(message.id, message.status)
        self._set_connection_status(self._connection_status_text)
        self.call_later(lambda c=message.contact_id: self._refresh_chat(c))

    async def _handle_relay_packet(self, payload: bytes) -> None:
        if self._connected_contact_id is None:
            logger.warning("Ignoring relay packet from an unverified connection.")
            return
        peer = self.db_manager.get_contact(self._connected_contact_id)
        if peer is None or peer.blocked:
            logger.info("Ignoring relay packet from a blocked or unknown contact.")
            return
        envelope = RelayEnvelope.decode(payload)
        is_new = self.db_manager.remember_relay(envelope.packet_id)
        if envelope.destination == self.key_manager.identity_hex:
            if envelope.kind == "message":
                delivery_id = bytes.fromhex(envelope.packet_id)
                if is_new:
                    delivered = await self._handle_text_message(
                        envelope.payload, envelope.source, delivery_id
                    )
                    if not delivered:
                        self.db_manager.forget_relay(envelope.packet_id)
                else:
                    await self._send_relay_ack(envelope.source, delivery_id)
            else:
                if not is_new:
                    return
                self._handle_ack_payload(envelope.payload)
            return
        if envelope.hops_left <= 0:
            return
        incoming_peer = self._connected_peer_public_key()
        if not is_new:
            prior = next(
                (via for packet_id, _, via in self.db_manager.get_queued_relays() if packet_id == envelope.packet_id),
                None,
            )
            if prior == incoming_peer:
                return
        envelope.hops_left -= 1
        self.db_manager.queue_relay(
            envelope.packet_id,
            envelope.encode(),
            incoming_peer,
        )
        self.notify("Encrypted message saved for relay to a later contact.", severity="information")

    async def _handle_key_exchange(self, payload: bytes) -> None:
        """Handle an incoming key exchange bundle."""
        try:
            bundle = json.loads(payload.decode("utf-8"))
            if not KeyManager.verify_peer_bundle(bundle):
                logger.warning("Invalid key exchange bundle received.")
                return

            public_key = bundle["public_key"].lower()
            verify_key = bundle["verify_key"].lower()
            existing = self.db_manager.get_contact_by_public_key(public_key)
            if existing:
                if existing.verify_key != verify_key:
                    self.notify("This contact's identity key changed. Verify it before continuing.", severity="error")
                    return
                await self._accept_peer_bundle(bundle, existing)
            else:
                fingerprint = self._peer_fingerprint(self.key_manager.identity_hex, verify_key)
                self.push_screen(VerifyPeerScreen(bundle, fingerprint))

        except Exception as exc:
            logger.error("Key exchange failed: %s", exc, exc_info=True)

    async def _accept_peer_bundle(self, bundle: dict[str, str], contact: Contact | None = None) -> None:
        public_key = bundle["public_key"].lower()
        verify_key = bundle["verify_key"].lower()
        contact = contact or self.db_manager.get_contact_by_public_key(public_key)
        if contact is None:
            contact = Contact(name=public_key[:8], public_key=public_key, verify_key=verify_key)
        elif contact.verify_key != verify_key:
            self.notify("The contact identity key changed. Contact was not updated.", severity="error")
            return
        if contact.blocked:
            logger.info("Ignoring connection from blocked contact %s", contact.short_id)
            return
        contact.last_seen = time.time()
        self.db_manager.save_contact(contact)
        self._connected_contact_id = contact.id
        self.call_later(self._refresh_ui)

        if bundle.get("reply", True) and self.transport and self.transport.is_connected():
            my_bundle = self.key_manager.get_public_bundle()
            my_bundle["reply"] = False
            payload = json.dumps(my_bundle).encode()
            for chunk in self._chunk_message(MessageType.KEY_EXCHANGE, payload):
                await self.transport.send(chunk.to_bytes())
        await self._forward_queued_relays(contact)
        await self._flush_pending_messages(contact)

    @staticmethod
    def _peer_fingerprint(first_key: str, second_key: str) -> str:
        keys = sorted((bytes.fromhex(first_key), bytes.fromhex(second_key)))
        digest = hashlib.sha256(b"PhantomMessenger-Contact-Check-v1" + b"".join(keys)).hexdigest()[:16]
        return " ".join(digest[i : i + 4].upper() for i in range(0, len(digest), 4))

    async def _flush_pending_messages(self, contact: Contact) -> None:
        if not self.transport or not self.transport.is_connected():
            return
        awaiting_ack = {message.id for message in self._pending_deliveries.values()}
        for target in self.db_manager.get_all_contacts():
            if target.blocked:
                continue
            for message in self.db_manager.get_undelivered_messages(target.id):
                if not self.transport.is_connected():
                    return
                if message.id in awaiting_ack or message.id in self._sending_message_ids:
                    continue
                message.status = MessageStatus.PENDING
                self.db_manager.update_message_status(message.id, message.status)
                await self._transmit_message(target, message)

    async def _forward_queued_relays(self, peer: Contact) -> None:
        if not self.transport or not self.transport.is_connected():
            return
        for packet_id, raw, via in self.db_manager.get_queued_relays():
            if via == peer.public_key:
                continue
            envelope = RelayEnvelope.decode(raw)
            if envelope.hops_left <= 0:
                continue
            envelope.hops_left -= 1
            forwarded = envelope.encode()
            for chunk in self._chunk_message(MessageType.RELAY_MESSAGE, forwarded):
                await self.transport.send(chunk.to_bytes())
            self.db_manager.queue_relay(packet_id, forwarded, peer.public_key)

    async def _handle_text_message(
        self,
        payload: bytes,
        expected_source: str | None = None,
        relay_delivery_id: bytes | None = None,
    ) -> bool:
        """Decrypt and store an incoming text message."""
        from nacl.signing import VerifyKey
        from nacl.encoding import HexEncoder

        contacts = self.db_manager.get_all_contacts()
        matched_contact = None

        for contact in contacts:
            if contact.blocked:
                continue
            if expected_source and contact.verify_key != expected_source:
                continue
            try:
                encryptor = self._get_encryptor(contact)
                verify_key = VerifyKey(contact.verify_key.encode(), encoder=HexEncoder)
                plaintext, timestamp = encryptor.decrypt(payload, verify_key)

                msg = ChatMessage(
                    contact_id=contact.id,
                    content=plaintext,
                    timestamp=timestamp,
                    direction=MessageDirection.RECEIVED,
                    status=MessageStatus.DELIVERED,
                    is_read=False,
                )
                self.db_manager.save_message(msg)
                contact.last_seen = time.time()
                self.db_manager.save_contact(contact)

                logger.info("Received a message from %s", contact.name or contact.short_id)
                matched_contact = contact
                break

            except Exception:
                continue

        if matched_contact:
            if self.transport and self.transport.is_connected():
                delivery_id = relay_delivery_id or hashlib.sha256(payload).digest()
                signature = self.key_manager.signing_key.sign(delivery_id).signature
                ack_payload = delivery_id + signature
                if expected_source:
                    await self._send_relay_ack(expected_source, delivery_id)
                    ack_chunks = []
                else:
                    ack_chunks = self._chunk_message(MessageType.ACK, ack_payload)
                for chunk in ack_chunks:
                    await self.transport.send(chunk.to_bytes())
            # Schedule UI refresh via call_later so Textual's active_app context is set
            self.call_later(self._refresh_ui)
            self.call_later(lambda c=matched_contact: self._refresh_chat(c.id))
            return True
        else:
            logger.warning("Could not decrypt incoming message from any known contact.")
            return False

    async def _send_relay_ack(self, destination: str, delivery_id: bytes) -> None:
        if not self.transport or not self.transport.is_connected():
            return
        signature = self.key_manager.signing_key.sign(delivery_id).signature
        ack = RelayEnvelope.create(
            "ack", self.key_manager.identity_hex, destination, delivery_id + signature
        )
        encoded = ack.encode()
        self.db_manager.queue_relay(ack.packet_id, encoded, self._connected_peer_public_key())
        for chunk in self._chunk_message(MessageType.RELAY_MESSAGE, encoded):
            await self.transport.send(chunk.to_bytes())

    # ------------------------------------------------------------------
    # BLE Transport Management
    # ------------------------------------------------------------------

    @on(MainScreen.StartAdvertise)
    def handle_start_advertise(self, message: MainScreen.StartAdvertise) -> None:
        """Handle the Advertise button — start BLE peripheral."""
        if self.transport and isinstance(self.transport, BLEPeripheral) and self.transport.is_advertising():
            logger.warning("Already advertising!")
            return

        self.transport = BLEPeripheral()
        self._start_transport()
        logger.info("Starting BLE advertising...")

        # Update button label
        try:
            btn = self.query_one("#advertise-btn", Button)
            btn.label = "Advertising..."
            btn.variant = "success"
        except NoMatches:
            pass

    @work(thread=False)
    async def _start_transport(self) -> None:
        """Start the BLE transport (peripheral mode by default)."""
        if self.transport:
            self.transport.set_callbacks(
                on_data=self._on_data_received,
                on_connect=self._on_peer_connected,
                on_disconnect=self._on_peer_disconnected,
            )
            try:
                await self.transport.start()
                if isinstance(self.transport, BLEPeripheral) and self.transport.is_advertising():
                    self._set_connection_status("Advertising and waiting for a device.")
            except Exception as exc:
                logger.error("Failed to start BLE transport: %s", exc)
                logger.error(f"Advertising failed: {exc}")
                # Reset button
                try:
                    btn = self.query_one("#advertise-btn", Button)
                    btn.label = "Advertise"
                    btn.variant = "default"
                except NoMatches:
                    pass

    async def _on_peer_connected(self) -> None:
        logger.info("Peer connected via BLE!")
        self._set_connection_status("Connected to a nearby device.")

    async def _on_peer_disconnected(self) -> None:
        logger.warning("Peer disconnected.")
        self._connected_contact_id = None
        self._pending_deliveries.clear()
        if isinstance(self.transport, BLEPeripheral) and self.transport.is_advertising():
            status = "Advertising and waiting for a device."
        else:
            status = "Disconnected. Pending messages will send when reconnected."
        self._set_connection_status(status)
        self._refresh_ui()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_encryptor(self, contact: Contact) -> MessageEncryptor:
        """Get or create a MessageEncryptor for a contact."""
        if contact.id not in self._encryptors:
            shared_secret = self.key_manager.compute_shared_secret(contact.public_key)
            self._encryptors[contact.id] = MessageEncryptor(
                shared_secret=shared_secret,
                signing_key=self.key_manager.signing_key,
            )
        return self._encryptors[contact.id]

    def _connected_peer_public_key(self) -> str:
        peer = self.db_manager.get_contact(self._connected_contact_id) if self._connected_contact_id else None
        return peer.public_key if peer else ""

    def _set_connection_status(self, status: str) -> None:
        self._connection_status_text = status
        queued = self.db_manager.get_pending_count()
        if queued:
            status = f"{status} {queued} message(s) queued."
        for screen in self.screen_stack:
            if isinstance(screen, MainScreen):
                try:
                    screen.query_one("#connection-status", Static).update(status)
                except NoMatches:
                    pass
                break

    def _relay_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, raw, _, _ in self.db_manager.get_relay_queue_details():
            try:
                destination = RelayEnvelope.decode(raw).destination
            except ValueError:
                continue
            counts[destination] = counts.get(destination, 0) + 1
        return counts

    def _relay_dashboard_entries(self) -> list[str]:
        contacts = {contact.verify_key: contact for contact in self.db_manager.get_all_contacts()}
        public_keys = {contact.public_key: contact for contact in contacts.values()}
        entries = []
        for _, raw, via, created_at in self.db_manager.get_relay_queue_details():
            try:
                envelope = RelayEnvelope.decode(raw)
            except ValueError:
                continue
            destination = contacts.get(envelope.destination)
            destination_name = destination.name if destination else envelope.destination[:8]
            previous_peer = public_keys.get(via)
            route = "ready to forward" if not via else f"last sent through {previous_peer.name if previous_peer else via[:8]}"
            age = max(0, int(time.time() - created_at))
            kind = "Message" if envelope.kind == "message" else "Delivery receipt"
            entries.append(
                f"{kind} for {destination_name}\n"
                f"{route}; {MAX_HOPS - envelope.hops_left}/{MAX_HOPS} hops used; waiting {age}s"
            )
        return entries

    def _chunk_message(self, msg_type: MessageType, payload: bytes) -> list[Chunk]:
        max_payload = (
            self.transport.max_chunk_payload
            if self.transport is not None
            else MAX_CHUNK_PAYLOAD
        )
        return chunk_message(msg_type, payload, max_payload_size=max_payload)

    def _refresh_ui(self, query: str | None = None) -> None:
        """Refresh the sidebar contacts list."""
        current = next(
            (screen for screen in reversed(self.screen_stack) if isinstance(screen, MainScreen)),
            None,
        )
        if current is None:
            return
        if query is None:
            query = current.query_one("#contact-search", Input).value
        conversations = self.db_manager.get_conversations(query)
        current.refresh_contacts(
            conversations,
            connected_contact_id=self._connected_contact_id,
            relay_counts=self._relay_counts(),
        )

    def _refresh_chat(self, contact_id: str) -> None:
        """Refresh the chat panel for a specific contact."""
        current = next(
            (screen for screen in reversed(self.screen_stack) if isinstance(screen, MainScreen)),
            None,
        )
        if current is None:
            return
        contact = self.db_manager.get_contact(contact_id)
        if contact:
            messages = self.db_manager.get_messages(contact_id)
            current.refresh_messages(contact, messages)
            self._refresh_ui()

    @on(MainScreen.ShowKeys)
    def handle_show_keys(self, message: MainScreen.ShowKeys) -> None:
        """Show the user's public key identity."""
        self.action_show_identity()

    def action_show_identity(self) -> None:
        """Show the user's public key identity."""
        bundle = json.dumps(self.key_manager.get_public_bundle(), separators=(",", ":"))
        self.push_screen(KeyBundleScreen(bundle))

    def action_quit(self) -> None:
        """Graceful shutdown."""
        self.db_manager.close()
        self.exit()
