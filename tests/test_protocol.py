"""Unit tests for the protocol module."""

import pytest

from messenger.transport.protocol import (
    Chunk,
    ChunkAssembler,
    MessageType,
    chunk_message,
)
from messenger.config import MAX_CHUNK_PAYLOAD


class TestChunkSerialization:
    """Tests for chunk serialization and deserialization."""

    def test_single_chunk_roundtrip(self):
        chunk = Chunk(
            msg_type=MessageType.TEXT_MESSAGE,
            sequence=0,
            total=1,
            payload=b"hello world",
        )
        data = chunk.to_bytes()
        restored = Chunk.from_bytes(data)

        assert restored.msg_type == MessageType.TEXT_MESSAGE
        assert restored.sequence == 0
        assert restored.total == 1
        assert restored.payload == b"hello world"

    def test_all_message_types(self):
        for mt in MessageType:
            chunk = Chunk(msg_type=mt, sequence=0, total=1, payload=b"test")
            data = chunk.to_bytes()
            restored = Chunk.from_bytes(data)
            assert restored.msg_type == mt

    def test_empty_payload(self):
        chunk = Chunk(msg_type=MessageType.ACK, sequence=0, total=1, payload=b"")
        data = chunk.to_bytes()
        restored = Chunk.from_bytes(data)
        assert restored.payload == b""

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            Chunk.from_bytes(b"\x01\x00")


class TestChunking:
    """Tests for message chunking."""

    def test_small_message_single_chunk(self):
        chunks = chunk_message(MessageType.TEXT_MESSAGE, b"small")
        assert len(chunks) == 1
        assert chunks[0].sequence == 0
        assert chunks[0].total == 1
        assert chunks[0].payload == b"small"

    def test_large_message_multiple_chunks(self):
        # Create a payload larger than MAX_CHUNK_PAYLOAD
        big_payload = b"X" * (MAX_CHUNK_PAYLOAD * 3 + 100)
        chunks = chunk_message(MessageType.TEXT_MESSAGE, big_payload)

        assert len(chunks) == 4
        for i, chunk in enumerate(chunks):
            assert chunk.sequence == i
            assert chunk.total == 4

        # Reassemble and verify
        reconstructed = b"".join(c.payload for c in chunks)
        assert reconstructed == big_payload

    def test_exact_mtu_boundary(self):
        payload = b"Y" * MAX_CHUNK_PAYLOAD
        chunks = chunk_message(MessageType.TEXT_MESSAGE, payload)
        assert len(chunks) == 1

    def test_one_byte_over_mtu(self):
        payload = b"Z" * (MAX_CHUNK_PAYLOAD + 1)
        chunks = chunk_message(MessageType.TEXT_MESSAGE, payload)
        assert len(chunks) == 2


class TestChunkAssembler:
    """Tests for chunk reassembly."""

    def test_single_chunk_assembly(self):
        assembler = ChunkAssembler()
        chunk = Chunk(
            msg_type=MessageType.TEXT_MESSAGE,
            sequence=0,
            total=1,
            payload=b"complete",
        )
        result = assembler.feed(chunk)
        assert result is not None
        msg_type, payload = result
        assert msg_type == MessageType.TEXT_MESSAGE
        assert payload == b"complete"

    def test_multi_chunk_assembly(self):
        assembler = ChunkAssembler()

        chunks = chunk_message(
            MessageType.TEXT_MESSAGE, b"A" * (MAX_CHUNK_PAYLOAD * 2 + 50)
        )

        for i, chunk in enumerate(chunks):
            result = assembler.feed(chunk)
            if i < len(chunks) - 1:
                assert result is None  # Not complete yet
            else:
                assert result is not None

        msg_type, payload = result
        assert payload == b"A" * (MAX_CHUNK_PAYLOAD * 2 + 50)

    def test_out_of_order_assembly(self):
        assembler = ChunkAssembler()

        chunks = chunk_message(
            MessageType.TEXT_MESSAGE, b"B" * (MAX_CHUNK_PAYLOAD * 2 + 10)
        )

        # Feed in reverse order
        for chunk in reversed(chunks):
            result = assembler.feed(chunk)

        assert result is not None
        _, payload = result
        assert payload == b"B" * (MAX_CHUNK_PAYLOAD * 2 + 10)

    def test_interleaved_message_types(self):
        assembler = ChunkAssembler()

        # Start a text message (2 chunks)
        text_chunks = [
            Chunk(MessageType.TEXT_MESSAGE, 0, 2, b"text_part1"),
            Chunk(MessageType.TEXT_MESSAGE, 1, 2, b"text_part2"),
        ]

        # Interleave with an ACK (1 chunk)
        ack_chunk = Chunk(MessageType.ACK, 0, 1, b"ack")

        assert assembler.feed(text_chunks[0]) is None
        result_ack = assembler.feed(ack_chunk)
        assert result_ack is not None
        assert result_ack[0] == MessageType.ACK

        result_text = assembler.feed(text_chunks[1])
        assert result_text is not None
        assert result_text[0] == MessageType.TEXT_MESSAGE
        assert result_text[1] == b"text_part1text_part2"

    def test_reset_clears_buffers(self):
        assembler = ChunkAssembler()
        assembler.feed(Chunk(MessageType.TEXT_MESSAGE, 0, 2, b"partial"))
        assembler.reset()

        # After reset, feeding the second chunk alone shouldn't complete
        result = assembler.feed(Chunk(MessageType.TEXT_MESSAGE, 1, 2, b"part2"))
        assert result is None
