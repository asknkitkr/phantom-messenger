"""
BLE message protocol — framing, chunking, and reassembly.

BLE has a limited MTU (~512 bytes), so larger messages must be split
into chunks and reassembled on the other side.

Wire format per chunk:
    [msg_type: 1 byte]
    [sequence: 2 bytes, big-endian]
    [total_chunks: 2 bytes, big-endian]
    [payload_length: 2 bytes, big-endian]
    [payload: variable]

Message types:
    0x01 = KEY_EXCHANGE    (initial public key bundle)
    0x02 = TEXT_MESSAGE     (encrypted text message)
    0x03 = ACK              (delivery acknowledgement)
    0x04 = DISCONNECT       (graceful disconnect)
"""

from __future__ import annotations

import struct
from enum import IntEnum
from dataclasses import dataclass, field

from messenger.config import HEADER_SIZE, MAX_CHUNK_PAYLOAD


class MessageType(IntEnum):
    """Protocol message types."""
    KEY_EXCHANGE = 0x01
    TEXT_MESSAGE = 0x02
    ACK = 0x03
    DISCONNECT = 0x04


@dataclass
class Chunk:
    """A single chunk of a framed message."""
    msg_type: MessageType
    sequence: int        # 0-based chunk index
    total: int           # total number of chunks in this message
    payload: bytes

    def to_bytes(self) -> bytes:
        """Serialise this chunk to wire format."""
        header = struct.pack(
            ">BHHH",
            self.msg_type,
            self.sequence,
            self.total,
            len(self.payload),
        )
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Chunk":
        """Deserialise a chunk from wire format."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Chunk too short: {len(data)} < {HEADER_SIZE}")

        msg_type, sequence, total, payload_len = struct.unpack(
            ">BHHH", data[:HEADER_SIZE]
        )

        payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]
        if len(payload) != payload_len:
            raise ValueError(
                f"Payload length mismatch: expected {payload_len}, got {len(payload)}"
            )

        return cls(
            msg_type=MessageType(msg_type),
            sequence=sequence,
            total=total,
            payload=payload,
        )


def chunk_message(msg_type: MessageType, payload: bytes) -> list[Chunk]:
    """Split a payload into BLE-sized chunks.

    Args:
        msg_type: The protocol message type.
        payload: The full message payload to chunk.

    Returns:
        A list of Chunk objects that together carry the full payload.
    """
    if len(payload) <= MAX_CHUNK_PAYLOAD:
        return [Chunk(msg_type=msg_type, sequence=0, total=1, payload=payload)]

    chunks: list[Chunk] = []
    offset = 0
    while offset < len(payload):
        chunk_data = payload[offset : offset + MAX_CHUNK_PAYLOAD]
        chunks.append(
            Chunk(
                msg_type=msg_type,
                sequence=len(chunks),
                total=0,  # filled in below
                payload=chunk_data,
            )
        )
        offset += MAX_CHUNK_PAYLOAD

    # Set the total count on every chunk
    for c in chunks:
        c.total = len(chunks)

    return chunks


@dataclass
class ChunkAssembler:
    """Reassembles chunks into complete messages.

    Buffers incoming chunks and yields complete message payloads
    when all chunks of a message have been received.
    """

    _buffers: dict[MessageType, dict[int, bytes]] = field(default_factory=dict)
    _totals: dict[MessageType, int] = field(default_factory=dict)

    def feed(self, chunk: Chunk) -> tuple[MessageType, bytes] | None:
        """Feed a received chunk into the assembler.

        Args:
            chunk: The received chunk.

        Returns:
            A (msg_type, full_payload) tuple if the message is complete,
            or None if more chunks are needed.
        """
        key = chunk.msg_type

        if key not in self._buffers:
            self._buffers[key] = {}
            self._totals[key] = chunk.total

        self._buffers[key][chunk.sequence] = chunk.payload

        # Check if we have all chunks
        if len(self._buffers[key]) == self._totals[key]:
            # Reassemble in order
            full_payload = b"".join(
                self._buffers[key][i] for i in range(self._totals[key])
            )
            # Clean up
            del self._buffers[key]
            del self._totals[key]
            return (key, full_payload)

        return None

    def reset(self) -> None:
        """Clear all buffers."""
        self._buffers.clear()
        self._totals.clear()
