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
import time
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

logger = logging.getLogger(__name__)


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
    align: center middle;
    width: 70;
    height: auto;
    max-height: 30;
    border: heavy $accent;
    padding: 2 4;
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


# ======================================================================
# Main Screen
# ======================================================================


class MainScreen(Screen):
    """Main interface with contact sidebar + chat panel."""

    BINDINGS = [
        Binding("ctrl+n", "scan", "Scan for Devices"),
        Binding("ctrl+a", "advertise", "Advertise"),
        Binding("ctrl+k", "show_keys", "My Keys"),
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
                yield Static("  CONTACTS", id="sidebar-header")
                yield ListView(id="contact-list")
                yield Button("+ Scan", variant="primary", id="add-contact-btn")
                yield Button("Advertise", variant="default", id="advertise-btn")
                yield Button("My Keys", variant="default", id="show-keys-btn")
            with Vertical(id="right-panel"):
                with Vertical(id="chat-panel"):
                    yield Static("  Select a contact", id="chat-header", markup=False)
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
                            placeholder="Type a message...",
                            id="message-input",
                            max_length=MAX_MESSAGE_LENGTH,
                        )
                        yield Button("Send", variant="primary", id="send-btn")
        yield Footer()

    def on_mount(self) -> None:
        """When MainScreen is fully mounted, ask the app to populate contacts."""
        self.app.post_message(self.RefreshRequest())

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

    @on(Button.Pressed, "#add-contact-btn")
    def handle_scan_btn(self) -> None:
        self.action_scan()

    def action_scan(self) -> None:
        self.app.push_screen(ScanScreen())

    @on(Button.Pressed, "#advertise-btn")
    def handle_advertise_btn(self) -> None:
        self.action_advertise()

    def action_advertise(self) -> None:
        self.app.post_message(self.StartAdvertise())

    class StartAdvertise(TMessage):
        pass

    @on(Button.Pressed, "#show-keys-btn")
    def handle_show_keys_btn(self) -> None:
        self.action_show_keys()

    def action_show_keys(self) -> None:
        self.app.post_message(self.ShowKeys())

    class ShowKeys(TMessage):
        pass

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
                logger.info(f"Contact selected: {self.selected_contact}")
                self.app.post_message(self.ContactSelected(self.selected_contact))

    # Maps ListView index → contact_id (avoids DuplicateIds with widget IDs)
    _contact_index_map: dict[int, str] = {}

    def refresh_contacts(self, conversations: list[Conversation]) -> None:
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
            name_text = f"{c.name or c.short_id}{unread}"
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
        header.update(f"  {contact.name or contact.short_id}")

        container = self.query_one("#chat-messages", ScrollableContainer)
        container.remove_children()

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

            line = Static(
                f"[{msg.time_display}] {prefix}: {msg.content}{delivery_status}",
                classes=f"msg-row {direction_class}",
                markup=False,
            )
            container.mount(line)

        # Scroll to bottom
        container.scroll_end(animate=False)

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
        self.key_manager = key_manager
        self.db_manager = db_manager
        self.transport = transport
        self._assembler = ChunkAssembler()
        self._encryptors: dict[str, MessageEncryptor] = {}
        self._pending_deliveries: dict[bytes, ChatMessage] = {}
        self._sending_message_ids: set[str] = set()


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

    @on(MainScreen.ContactSelected)
    def handle_contact_selected(self, message: MainScreen.ContactSelected) -> None:
        contact = self.db_manager.get_contact(message.contact_id)
        if contact is None:
            return

        messages = self.db_manager.get_messages(contact.id)
        self.db_manager.mark_messages_read(contact.id)

        current = self.screen
        if isinstance(current, MainScreen):
            current.refresh_messages(contact, messages)

    @on(MainScreen.SendMessage)
    def handle_send_message(self, message: MainScreen.SendMessage) -> None:
        contact = self.db_manager.get_contact(message.contact_id)
        if contact is None:
            return

        # Create message record
        chat_msg = ChatMessage(
            contact_id=contact.id,
            content=message.text,
            direction=MessageDirection.SENT,
            status=MessageStatus.PENDING,
        )
        self.db_manager.save_message(chat_msg)

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
            delivery_id = hashlib.sha256(encrypted).digest()

            chunks = self._chunk_message(MessageType.TEXT_MESSAGE, encrypted)

            if self.transport and self.transport.is_connected():
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
            if len(payload) == 96:
                delivery_id, signature = payload[:32], payload[32:]
                message = self._pending_deliveries.get(delivery_id)
                contact = self.db_manager.get_contact(message.contact_id) if message else None
                if contact is not None:
                    try:
                        from nacl.encoding import HexEncoder
                        from nacl.signing import VerifyKey

                        VerifyKey(contact.verify_key.encode(), encoder=HexEncoder).verify(
                            delivery_id, signature
                        )
                    except Exception:
                        logger.warning("Ignoring an invalid delivery acknowledgement.")
                    else:
                        self._pending_deliveries.pop(delivery_id, None)
                        message.status = MessageStatus.DELIVERED
                        self.db_manager.update_message_status(message.id, message.status)
                        self.call_later(lambda c=message.contact_id: self._refresh_chat(c))

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
                contact = existing
                existing.last_seen = time.time()
                self.db_manager.save_contact(existing)
                logger.info(f"Reconnected with {existing.name}")
            else:
                contact = Contact(
                    name=public_key[:8],
                    public_key=public_key,
                    verify_key=verify_key,
                    last_seen=time.time(),
                )
                self.db_manager.save_contact(contact)
                logger.info(f"New contact saved: {contact.name}")

            self.call_later(self._refresh_ui)

            # Reply with our keys if expected
            if bundle.get("reply", True) and self.transport and self.transport.is_connected():
                my_bundle = self.key_manager.get_public_bundle()
                my_bundle["reply"] = False
                reply_payload = json.dumps(my_bundle).encode()
                chunks = self._chunk_message(MessageType.KEY_EXCHANGE, reply_payload)
                for chunk in chunks:
                    await self.transport.send(chunk.to_bytes())

            await self._flush_pending_messages(contact)

        except Exception as exc:
            logger.error("Key exchange failed: %s", exc, exc_info=True)

    async def _flush_pending_messages(self, contact: Contact) -> None:
        if not self.transport or not self.transport.is_connected():
            return
        awaiting_ack = {message.id for message in self._pending_deliveries.values()}
        for message in self.db_manager.get_undelivered_messages(contact.id):
            if not self.transport.is_connected():
                break
            if message.id in awaiting_ack or message.id in self._sending_message_ids:
                continue
            message.status = MessageStatus.PENDING
            self.db_manager.update_message_status(message.id, message.status)
            await self._transmit_message(contact, message)

    async def _handle_text_message(self, payload: bytes) -> None:
        """Decrypt and store an incoming text message."""
        from nacl.signing import VerifyKey
        from nacl.encoding import HexEncoder

        contacts = self.db_manager.get_all_contacts()
        matched_contact = None

        for contact in contacts:
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
                delivery_id = hashlib.sha256(payload).digest()
                signature = self.key_manager.signing_key.sign(delivery_id).signature
                ack_chunks = self._chunk_message(
                    MessageType.ACK, delivery_id + signature
                )
                for chunk in ack_chunks:
                    await self.transport.send(chunk.to_bytes())
            # Schedule UI refresh via call_later so Textual's active_app context is set
            self.call_later(self._refresh_ui)
            self.call_later(lambda c=matched_contact: self._refresh_chat(c.id))
        else:
            logger.warning("Could not decrypt incoming message from any known contact.")

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
        self._pending_deliveries.clear()
        if isinstance(self.transport, BLEPeripheral) and self.transport.is_advertising():
            status = "Advertising and waiting for a device."
        else:
            status = "Disconnected. Pending messages will send when reconnected."
        self._set_connection_status(status)

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

    def _set_connection_status(self, status: str) -> None:
        for screen in self.screen_stack:
            if isinstance(screen, MainScreen):
                try:
                    screen.query_one("#connection-status", Static).update(status)
                except NoMatches:
                    pass
                break

    def _chunk_message(self, msg_type: MessageType, payload: bytes) -> list[Chunk]:
        max_payload = (
            self.transport.max_chunk_payload
            if self.transport is not None
            else MAX_CHUNK_PAYLOAD
        )
        return chunk_message(msg_type, payload, max_payload_size=max_payload)

    def _refresh_ui(self) -> None:
        """Refresh the sidebar contacts list."""
        current = next(
            (screen for screen in reversed(self.screen_stack) if isinstance(screen, MainScreen)),
            None,
        )
        if current is None:
            return
        conversations = self.db_manager.get_conversations()
        current.refresh_contacts(conversations)

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
