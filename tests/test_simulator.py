import pytest

from messenger.simulator import run_simulation
from messenger.config import MAX_CHUNK_PAYLOAD
from messenger.storage.models import MessageStatus


@pytest.mark.asyncio
async def test_simulator_delivers_an_encrypted_message(tmp_path):
    result = await run_simulation("Hello, Bob!", tmp_path)

    assert result.message == "Hello, Bob!"
    assert result.sender_status == MessageStatus.DELIVERED
    assert result.receiver_messages == 1


@pytest.mark.asyncio
async def test_simulator_reassembles_a_chunked_message(tmp_path):
    message = "x" * (MAX_CHUNK_PAYLOAD * 3)

    result = await run_simulation(message, tmp_path)

    assert result.message == message
    assert result.sender_status == MessageStatus.DELIVERED
