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
import json
import logging
import time
from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
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
)

from messenger.config import DATA_DIR, MAX_MESSAGE_LENGTH
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
#login-container {
    align: center middle;
    width: 60;
    height: auto;
    max-height: 24;
    border: heavy $primary;
    padding: 2 4;
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
    height: 100%;
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
    dock: bottom;
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
        yield Container(
            Static("PHANTOM MESSENGER", id="login-title"),
            Static("Offline  .  Encrypted  .  Secure", id="login-subtitle"),
            Input(
                placeholder="Enter your passphrase...",
                password=True,
                id="passphrase-input",
            ),
            Button("Unlock", variant="primary", classes="login-btn", id="unlock-btn"),
            Button(
                "Create New Identity",
                variant="default",
                classes="login-btn",
                id="create-btn",
            ),
            Static("", id="login-error"),
            id="login-container",
        )

    @on(Button.Pressed, "#unlock-btn")
    def handle_unlock(self) -> None:
        passphrase = self.query_one("#passphrase-input", Input).value.strip()
        if not passphrase:
            self._show_error("Passphrase cannot be empty.")
            return
        self.app.post_message(self.Unlock(passphrase))

    @on(Button.Pressed, "#create-btn")
    def handle_create(self) -> None:
        passphrase = self.query_one("#passphrase-input", Input).value.strip()
        if not passphrase:
            self._show_error("Enter a passphrase to protect your identity.")
            return
        if len(passphrase) < 8:
            self._show_error("Passphrase must be at least 8 characters.")
            return
        self.app.post_message(self.CreateIdentity(passphrase))

    @on(Input.Submitted, "#passphrase-input")
    def handle_submit(self) -> None:
        passphrase = self.query_one("#passphrase-input", Input).value.strip()
        if not passphrase:
            return
        # Try unlock first; if no keys exist, the app will handle it
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
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield Static("  CONTACTS", id="sidebar-header")
                yield ListView(id="contact-list")
                yield Button("+ Scan", variant="primary", id="add-contact-btn")
                yield Button("📡 Advertise", variant="default", id="advertise-btn")
                yield Button("🔑 My Keys", variant="default", id="show-keys-btn")
            with Vertical(id="right-panel"):
                with Vertical(id="chat-panel"):
                    yield Static("  Select a contact", id="chat-header")
                    yield ScrollableContainer(
                        Static(
                            "Select a contact to start chatting\n\n"
                            "Press Ctrl+N to scan for nearby devices",
                            classes="empty-chat-placeholder",
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
        text = inp.value.strip()

        logger.debug(
            "handle_send: text=%r, selected_contact=%r",
            text[:20] if text else None,
            self.selected_contact,
        )

        if not text:
            self.notify("Please type a message first.", severity="warning")
            return
        if self.selected_contact is None:
            self.notify("Please select a contact first.", severity="warning")
            return

        if not MessageEncryptor.is_valid_text(text):
            self.notify(
                "Only plain text allowed (no emoji or special characters).",
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
    @on(ListView.Highlighted, "#contact-list")
    def handle_contact_selected(self, event: ListView.Selected | ListView.Highlighted) -> None:
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
                Label(name_text, classes="contact-name"),
                Label(preview, classes="contact-preview"),
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
            status_icon = ""
            if msg.direction == MessageDirection.SENT:
                if msg.status == MessageStatus.DELIVERED:
                    status_icon = " [ok]"
                elif msg.status == MessageStatus.FAILED:
                    status_icon = " [!]"
                else:
                    status_icon = " [...]"

            line = Static(
                f"[{msg.time_display}] {prefix}: {msg.content}{status_icon}",
                classes=f"msg-row {direction_class}",
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
            Static("Searching for nearby Phantom devices...", id="scan-status"),
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

        status.update("🔍 Scanning for BLE devices...")
        refresh_btn = self.query_one("#scan-refresh-btn", Button)
        refresh_btn.disabled = True
        refresh_btn.label = "⏳ Scanning..."
        try:
            central = BLECentral()
            devices = await central.scan(timeout=5.0)
            if devices:
                status.update(f"Found {len(devices)} device(s):")
                for dev in devices:
                    item = ListItem(
                        Label(
                            f"{dev['name']} ({dev['address']}) RSSI: {dev['rssi']}",
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
            status.update(f"Scan failed: {exc}\nTry adding a contact manually.")
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


class ManualAddScreen(Screen):
    """Manually add a contact by pasting their public key bundle."""

    BINDINGS = [
        Binding("escape", "dismiss", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("ADD CONTACT MANUALLY", id="scan-title"),
            Static(
                "Paste the other user's public key (hex):",
                id="scan-status",
            ),
            Input(placeholder="Contact name", id="manual-name"),
            Input(placeholder="X25519 public key (hex, 64 chars)", id="manual-pubkey"),
            Input(placeholder="Ed25519 verify key (hex, 64 chars)", id="manual-verifykey"),
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
        pubkey = self.query_one("#manual-pubkey", Input).value.strip()
        verifykey = self.query_one("#manual-verifykey", Input).value.strip()

        if not name:
            name = pubkey[:8] if pubkey else "Unknown"

        if len(pubkey) != 64 or len(verifykey) != 64:
            err = self.query_one("#login-error", Static)
            err.update("Keys must be exactly 64 hex characters each.")
            err.styles.display = "block"
            return

        self.app.post_message(
            self.ManualContactAdd(name=name, public_key=pubkey, verify_key=verifykey)
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
    SUB_TITLE = "Offline . Encrypted . Secure"
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


    def on_unmount(self) -> None:
        if self.transport:
            asyncio.create_task(self.transport.stop())

    def on_mount(self) -> None:
        self.push_screen(LoginScreen())

    # ------------------------------------------------------------------
    # Login Handlers
    # ------------------------------------------------------------------

    @on(LoginScreen.Unlock)
    def handle_unlock(self, message: LoginScreen.Unlock) -> None:
        passphrase = message.passphrase

        if not self.key_manager.has_keys():
            self.notify(
                "No identity found. Click 'Create New Identity' first.",
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

        self.key_manager.generate()
        self.key_manager.save(passphrase)

        if not self.key_manager.load(passphrase):
            self.notify("Failed to load newly created keys.", severity="error")
            return

        if not self.db_manager.open(passphrase):
            self.notify(
                f"Failed to create database: check {DATA_DIR / 'phantom.log'}",
                severity="error",
            )
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
            # No BLE connection — save as delivered locally
            chat_msg.status = MessageStatus.DELIVERED
            self.db_manager.update_message_status(chat_msg.id, chat_msg.status)
            self._refresh_chat(contact.id)

    @work(thread=False)
    async def _send_encrypted(self, contact: Contact, chat_msg: ChatMessage) -> None:
        """Encrypt and send a message via BLE transport."""
        try:
            encryptor = self._get_encryptor(contact)
            encrypted = encryptor.encrypt(chat_msg.content)

            chunks = chunk_message(MessageType.TEXT_MESSAGE, encrypted)

            if self.transport and self.transport.is_connected():
                for chunk in chunks:
                    await self.transport.send(chunk.to_bytes())

                # Mark as delivered
                chat_msg.status = MessageStatus.DELIVERED
            else:
                chat_msg.status = MessageStatus.FAILED
                logger.warning("Not connected. Message queued.")

        except Exception as exc:
            logger.error("Failed to send message: %s", exc)
            chat_msg.status = MessageStatus.FAILED
            logger.error(f"Send failed: {exc}")

        self.db_manager.update_message_status(chat_msg.id, chat_msg.status)
        self._refresh_chat(contact.id)

    # ------------------------------------------------------------------
    # Manual Contact Add
    # ------------------------------------------------------------------

    @on(ManualAddScreen.ManualContactAdd)
    def handle_manual_add(self, message: ManualAddScreen.ManualContactAdd) -> None:
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
        central.set_callbacks(on_data=self._on_data_received)

        if await central.connect_to(address):
            self.transport = central

            try:
                # Send our key bundle
                bundle = json.dumps(self.key_manager.get_public_bundle()).encode()
                chunks = chunk_message(MessageType.KEY_EXCHANGE, bundle)
                for chunk in chunks:
                    await central.send(chunk.to_bytes())

                logger.info("Connected and key exchange sent!")
            except Exception as exc:
                logger.error("Failed to send key bundle: %s", exc)
        else:
            logger.error(f"Failed to connect to {address}.")

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
            pass  # TODO: handle delivery ACKs

    async def _handle_key_exchange(self, payload: bytes) -> None:
        """Handle an incoming key exchange bundle."""
        try:
            bundle = json.loads(payload.decode("utf-8"))
            if not KeyManager.verify_peer_bundle(bundle):
                logger.warning("Invalid key exchange bundle received.")
                return

            existing = self.db_manager.get_contact_by_public_key(bundle["public_key"])
            if existing:
                existing.last_seen = time.time()
                self.db_manager.save_contact(existing)
                logger.info(f"Reconnected with {existing.name}")
            else:
                contact = Contact(
                    name=bundle["public_key"][:8],
                    public_key=bundle["public_key"],
                    verify_key=bundle["verify_key"],
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
                chunks = chunk_message(MessageType.KEY_EXCHANGE, reply_payload)
                for chunk in chunks:
                    await self.transport.send(chunk.to_bytes())

        except Exception as exc:
            logger.error("Key exchange failed: %s", exc, exc_info=True)

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

                logger.info(f"Message received from {contact.name}: {plaintext[:30]}")
                matched_contact = contact
                break

            except Exception:
                continue

        if matched_contact:
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
        if self.transport and isinstance(self.transport, BLEPeripheral) and self.transport.is_connected():
            logger.warning("Already advertising!")
            return

        self.transport = BLEPeripheral()
        self._start_transport()
        logger.info("Starting BLE advertising...")

        # Update button label
        try:
            btn = self.query_one("#advertise-btn", Button)
            btn.label = "📡 Advertising…"
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
            except Exception as exc:
                logger.error("Failed to start BLE transport: %s", exc)
                logger.error(f"Advertising failed: {exc}")
                # Reset button
                try:
                    btn = self.query_one("#advertise-btn", Button)
                    btn.label = "📡 Advertise"
                    btn.variant = "default"
                except NoMatches:
                    pass

    async def _on_peer_connected(self) -> None:
        logger.info("Peer connected via BLE!")

    async def _on_peer_disconnected(self) -> None:
        logger.warning("Peer disconnected.")

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

    def _refresh_ui(self) -> None:
        """Refresh the sidebar contacts list."""
        current = self.screen
        if not isinstance(current, MainScreen):
            return
        conversations = self.db_manager.get_conversations()
        current.refresh_contacts(conversations)

    def _refresh_chat(self, contact_id: str) -> None:
        """Refresh the chat panel for a specific contact."""
        current = self.screen
        if not isinstance(current, MainScreen):
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
        self.notify(
            f"Your Identity (share with contacts):\n\n"
            f"Public Key:  {self.key_manager.public_key_hex}\n"
            f"Verify Key:  {self.key_manager.identity_hex}",
            severity="information",
            timeout=15,
        )

    def action_quit(self) -> None:
        """Graceful shutdown."""
        self.db_manager.close()
        self.exit()
