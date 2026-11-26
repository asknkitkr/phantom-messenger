"""
BLE message protocol — framing, chunking, and reassembly.

BLE has a limited MTU (~512 bytes), so larger messages must be split
into chunks and reassembled on the other side.

Wire format per chunk:
    [msg_type: 1 byte]
    [transfer_id: 4 bytes]
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

import secrets
import struct
from enum import IntEnum
from dataclasses import dataclass, field

from messenger.config import HEADER_SIZE, MAX_CHUNK_PAYLOAD, MAX_MESSAGE_LENGTH

_MIN_CHUNK_PAYLOAD = 23 - 3 - HEADER_SIZE
_MAX_CHUNKS = (MAX_MESSAGE_LENGTH * 4 + 2048 + _MIN_CHUNK_PAYLOAD - 1) // _MIN_CHUNK_PAYLOAD
_MAX_ASSEMBLED_BYTES = MAX_MESSAGE_LENGTH * 4 + 2048


class MessageType(IntEnum):
    """Protocol message types."""
    KEY_EXCHANGE = 0x01
    TEXT_MESSAGE = 0x02
    ACK = 0x03
    DISCONNECT = 0x04
    RELAY_MESSAGE = 0x05


@dataclass
class Chunk:
    """A single chunk of a framed message."""
    msg_type: MessageType
    sequence: int        # 0-based chunk index
    total: int           # total number of chunks in this message
    payload: bytes
    transfer_id: int = 0

    def to_bytes(self) -> bytes:
        """Serialise this chunk to wire format."""
        header = struct.pack(
            ">BIHHH",
            self.msg_type,
            self.transfer_id,
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

        msg_type, transfer_id, sequence, total, payload_len = struct.unpack(
            ">BIHHH", data[:HEADER_SIZE]
        )

        payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]
        if (
            len(payload) != payload_len
            or len(data) != HEADER_SIZE + payload_len
            or payload_len > MAX_CHUNK_PAYLOAD
        ):
            raise ValueError(
                f"Payload length mismatch: expected {payload_len}, got {len(payload)}"
            )

        return cls(
            msg_type=MessageType(msg_type),
            sequence=sequence,
            total=total,
            payload=payload,
            transfer_id=transfer_id,
        )


def chunk_message(
    msg_type: MessageType,
    payload: bytes,
    max_payload_size: int = MAX_CHUNK_PAYLOAD,
) -> list[Chunk]:
    """Split a payload into BLE-sized chunks.

    Args:
        msg_type: The protocol message type.
        payload: The full message payload to chunk.

    Returns:
        A list of Chunk objects that together carry the full payload.
    """
    if not 1 <= max_payload_size <= MAX_CHUNK_PAYLOAD:
        raise ValueError(f"Invalid chunk payload limit: {max_payload_size}")

    if len(payload) <= max_payload_size:
        return [
            Chunk(
                msg_type=msg_type,
                sequence=0,
                total=1,
                payload=payload,
                transfer_id=secrets.randbits(32),
            )
        ]

    transfer_id = secrets.randbits(32)
    chunks: list[Chunk] = []
    offset = 0
    while offset < len(payload):
        chunk_data = payload[offset : offset + max_payload_size]
        chunks.append(
            Chunk(
                msg_type=msg_type,
                sequence=len(chunks),
                total=0,  # filled in below
                payload=chunk_data,
                transfer_id=transfer_id,
            )
        )
        offset += max_payload_size

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

    _buffers: dict[tuple[MessageType, int], dict[int, bytes]] = field(default_factory=dict)
    _totals: dict[tuple[MessageType, int], int] = field(default_factory=dict)
    _sizes: dict[tuple[MessageType, int], int] = field(default_factory=dict)

    def feed(self, chunk: Chunk) -> tuple[MessageType, bytes] | None:
        """Feed a received chunk into the assembler.

        Args:
            chunk: The received chunk.

        Returns:
            A (msg_type, full_payload) tuple if the message is complete,
            or None if more chunks are needed.
        """
        if (
            chunk.total < 1
            or chunk.total > _MAX_CHUNKS
            or chunk.sequence >= chunk.total
        ):
            raise ValueError("Invalid chunk sequence or total")
        key = (chunk.msg_type, chunk.transfer_id)

        if key not in self._buffers:
            if len(self._buffers) >= 16:
                oldest = next(iter(self._buffers))
                del self._buffers[oldest]
                del self._totals[oldest]
                del self._sizes[oldest]
            self._buffers[key] = {}
            self._totals[key] = chunk.total
            self._sizes[key] = 0
        elif self._totals[key] != chunk.total:
            del self._buffers[key]
            del self._totals[key]
            raise ValueError("Inconsistent chunk total")

        previous = self._buffers[key].get(chunk.sequence, b"")
        new_size = self._sizes[key] + len(chunk.payload) - len(previous)
        if new_size > _MAX_ASSEMBLED_BYTES:
            del self._buffers[key]
            del self._totals[key]
            del self._sizes[key]
            raise ValueError("Assembled message exceeds the maximum size")
        self._buffers[key][chunk.sequence] = chunk.payload
        self._sizes[key] = new_size

        # Check if we have all chunks
        if len(self._buffers[key]) == self._totals[key]:
            # Reassemble in order
            full_payload = b"".join(
                self._buffers[key][i] for i in range(self._totals[key])
            )
            # Clean up
            del self._buffers[key]
            del self._totals[key]
            del self._sizes[key]
            return (chunk.msg_type, full_payload)

        return None

    def reset(self) -> None:
        """Clear all buffers."""
        self._buffers.clear()
        self._totals.clear()
        self._sizes.clear()
