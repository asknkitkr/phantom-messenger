"""Run an end-to-end Phantom Messenger simulation without Bluetooth hardware."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey

from messenger.crypto.encryption import MessageEncryptor
from messenger.crypto.keys import KeyManager
from messenger.storage.database import DatabaseManager
from messenger.storage.models import Contact, Message, MessageDirection, MessageStatus
from messenger.transport.peripheral import LoopbackTransport
from messenger.transport.protocol import Chunk, ChunkAssembler, MessageType, chunk_message


@dataclass(frozen=True)
class SimulationResult:
    """Result of one successful simulated delivery."""

    message: str
    sender_status: MessageStatus
    receiver_messages: int
    data_dir: Path


class SimulatedPeer:
    """One local Phantom identity connected through the real loopback transport."""

    def __init__(self, name: str, data_dir: Path) -> None:
        self.name = name
        self.data_dir = data_dir / name.lower()
        self.key_manager = KeyManager(self.data_dir / "keys")
        self.key_manager.generate()
        self.database = DatabaseManager(self.data_dir / "phantom.db")
        if not self.database.open(f"{name}-simulator-passphrase"):
            raise RuntimeError("SQLCipher is required to run the simulator.")
        self.transport = LoopbackTransport(name)
        self.assembler = ChunkAssembler()
        self.contacts: dict[str, Contact] = {}
        self.pending: dict[bytes, Message] = {}
        self.delivered = asyncio.Event()

    def add_contact(self, peer: "SimulatedPeer") -> None:
        contact = Contact(
            name=peer.name,
            public_key=peer.key_manager.public_key_hex,
            verify_key=peer.key_manager.identity_hex,
        )
        self.database.save_contact(contact)
        self.contacts[contact.verify_key] = contact

    async def start(self) -> None:
        self.transport.set_callbacks(on_data=self._on_data)
        await self.transport.start()

    async def stop(self) -> None:
        await self.transport.stop()
        self.database.close()

    async def send(self, text: str, peer: "SimulatedPeer") -> Message:
        contact = self.contacts[peer.key_manager.identity_hex]
        message = Message(
            contact_id=contact.id,
            content=text,
            direction=MessageDirection.SENT,
            status=MessageStatus.PENDING,
        )
        self.database.save_message(message)

        encryptor = MessageEncryptor(
            self.key_manager.compute_shared_secret(contact.public_key),
            self.key_manager.signing_key,
        )
        encrypted = encryptor.encrypt(text)
        delivery_id = hashlib.sha256(encrypted).digest()
        self.pending[delivery_id] = message
        for chunk in chunk_message(MessageType.TEXT_MESSAGE, encrypted):
            await self.transport.send(chunk.to_bytes())
        return message

    async def _on_data(self, data: bytes) -> None:
        complete = self.assembler.feed(Chunk.from_bytes(data))
        if complete is None:
            return
        message_type, payload = complete
        if message_type == MessageType.TEXT_MESSAGE:
            await self._receive_message(payload)
        elif message_type == MessageType.ACK:
            self._receive_ack(payload)

    async def _receive_message(self, payload: bytes) -> None:
        for verify_key_hex, contact in self.contacts.items():
            try:
                decryptor = MessageEncryptor(
                    self.key_manager.compute_shared_secret(contact.public_key),
                    self.key_manager.signing_key,
                )
                plaintext, timestamp = decryptor.decrypt(
                    payload, VerifyKey(verify_key_hex.encode(), encoder=HexEncoder)
                )
            except Exception:
                continue

            self.database.save_message(
                Message(
                    contact_id=contact.id,
                    content=plaintext,
                    timestamp=timestamp,
                    direction=MessageDirection.RECEIVED,
                    status=MessageStatus.DELIVERED,
                )
            )
            delivery_id = hashlib.sha256(payload).digest()
            acknowledgement = delivery_id + self.key_manager.signing_key.sign(delivery_id).signature
            for chunk in chunk_message(MessageType.ACK, acknowledgement):
                await self.transport.send(chunk.to_bytes())
            return
        raise ValueError("Simulation received a message from an unknown peer.")

    def _receive_ack(self, payload: bytes) -> None:
        if len(payload) != 96:
            raise ValueError("Simulation received an invalid acknowledgement.")
        delivery_id, signature = payload[:32], payload[32:]
        message = self.pending.pop(delivery_id, None)
        if message is None:
            return
        contact = self.database.get_contact(message.contact_id)
        if contact is None:
            raise ValueError("Simulation acknowledgement has no matching contact.")
        VerifyKey(contact.verify_key.encode(), encoder=HexEncoder).verify(delivery_id, signature)
        message.status = MessageStatus.DELIVERED
        self.database.update_message_status(message.id, message.status)
        self.delivered.set()


async def run_simulation(message: str, data_dir: Path) -> SimulationResult:
    """Deliver one encrypted message between two virtual peers."""
    alice = SimulatedPeer("Alice", data_dir)
    bob = SimulatedPeer("Bob", data_dir)
    LoopbackTransport.link(alice.transport, bob.transport)
    alice.add_contact(bob)
    bob.add_contact(alice)

    try:
        await alice.start()
        await bob.start()
        sent = await alice.send(message, bob)
        await asyncio.wait_for(alice.delivered.wait(), timeout=2)
        received = bob.database.get_messages(bob.contacts[alice.key_manager.identity_hex].id)
        if len(received) != 1 or received[0].content != message:
            raise AssertionError("Simulation did not preserve the message.")
        return SimulationResult(message, sent.status, len(received), data_dir)
    finally:
        await alice.stop()
        await bob.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Phantom Messenger without Bluetooth hardware.")
    parser.add_argument("--message", default="Hello from the Phantom Messenger simulator.")
    parser.add_argument("--data-dir", type=Path, help="Keep simulation data in this directory.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    temporary_dir: tempfile.TemporaryDirectory[str] | None = None
    if args.data_dir:
        data_dir = args.data_dir.expanduser().resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
    else:
        temporary_dir = tempfile.TemporaryDirectory(prefix="phantom-simulator-")
        data_dir = Path(temporary_dir.name)

    try:
        result = asyncio.run(run_simulation(args.message, data_dir))
        print("Simulation passed")
        print(f"Delivered: {result.message}")
        print(f"Sender status: {result.sender_status.value}")
        print(f"Receiver messages: {result.receiver_messages}")
        if args.data_dir:
            print(f"Simulation data: {result.data_dir}")
    finally:
        if temporary_dir:
            temporary_dir.cleanup()


if __name__ == "__main__":
    main()
