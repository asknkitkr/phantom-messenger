"""
BLE Peripheral (Server) — advertises a GATT service and accepts connections.

Uses the Bless library to create a BLE peripheral that:
    1. Advertises a custom GATT service UUID
    2. Exposes TX (notify) and RX (write) characteristics
    3. Receives data from connected centrals via the RX characteristic
    4. Sends data to connected centrals via TX notifications

This module also includes a **loopback transport** that works via
asyncio queues for testing on a single machine without Bluetooth.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Callable, Awaitable, Optional

from messenger.config import (
    BLE_DEVICE_NAME,
    BLE_SERVICE_UUID,
    BLE_TX_CHAR_UUID,
    BLE_RX_CHAR_UUID,
)

logger = logging.getLogger(__name__)

# Type alias for the data-receive callback
OnDataReceived = Callable[[bytes], Awaitable[None]]


class BaseTransport(ABC):
    """Abstract base transport — implemented by BLE and loopback."""

    def __init__(self) -> None:
        self._on_data: OnDataReceived | None = None
        self._on_connect: Callable[[], Awaitable[None]] | None = None
        self._on_disconnect: Callable[[], Awaitable[None]] | None = None

    def set_callbacks(
        self,
        on_data: OnDataReceived,
        on_connect: Callable[[], Awaitable[None]] | None = None,
        on_disconnect: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._on_data = on_data
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect

    @abstractmethod
    async def start(self) -> None:
        """Start the transport (advertising / listening)."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the transport."""

    @abstractmethod
    async def send(self, data: bytes) -> None:
        """Send data to the connected peer."""

    @abstractmethod
    def is_connected(self) -> bool:
        """Whether a peer is currently connected."""


class BLEPeripheral(BaseTransport):
    """BLE Peripheral using Bless — acts as the GATT server.

    One device in each pair runs as the peripheral (advertiser).
    The other runs as the central (scanner/connector).
    """

    def __init__(self) -> None:
        super().__init__()
        self._server = None
        self._connected = False
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self) -> None:
        """Start advertising the GATT service."""
        try:
            from bless import (  # type: ignore[import-untyped]
                BlessServer,
                BlessGATTCharacteristic,
                GATTCharacteristicProperties,
                GATTAttributePermissions,
            )
        except ImportError:
            logger.error(
                "bless is not installed. Install it with: pip install bless"
            )
            raise

        self._loop = asyncio.get_running_loop()

        self._server = BlessServer(name=BLE_DEVICE_NAME, loop=self._loop)
        self._server.read_request_func = self._on_read
        self._server.write_request_func = self._on_write

        await self._server.add_new_service(BLE_SERVICE_UUID)

        # TX characteristic — notify (server pushes data to client)
        tx_flags = (
            GATTCharacteristicProperties.notify
            | GATTCharacteristicProperties.read
        )
        tx_perms = GATTAttributePermissions.readable
        await self._server.add_new_characteristic(
            BLE_SERVICE_UUID, BLE_TX_CHAR_UUID, tx_flags, None, tx_perms
        )

        # RX characteristic — write (client pushes data to server)
        rx_flags = (
            GATTCharacteristicProperties.write
            | GATTCharacteristicProperties.write_without_response
        )
        rx_perms = GATTAttributePermissions.writeable
        await self._server.add_new_characteristic(
            BLE_SERVICE_UUID, BLE_RX_CHAR_UUID, rx_flags, None, rx_perms
        )

        await self._server.start()
        self._connected = True
        logger.info("BLE peripheral started — advertising as '%s'", BLE_DEVICE_NAME)

        if self._on_connect:
            await self._on_connect()

    async def stop(self) -> None:
        """Stop advertising and disconnect."""
        if self._server:
            await self._server.stop()
            self._server = None
        self._connected = False
        logger.info("BLE peripheral stopped.")

        if self._on_disconnect:
            await self._on_disconnect()

    async def send(self, data: bytes) -> None:
        """Send data via TX characteristic notification."""
        if self._server is None:
            raise RuntimeError("Peripheral not started.")

        self._server.get_characteristic(BLE_TX_CHAR_UUID).value = data
        result = self._server.update_value(BLE_SERVICE_UUID, BLE_TX_CHAR_UUID)
        logger.info(f"Peripheral TX notification sent ({len(data)}b), result={result}")
        # macOS CoreBluetooth silently drops notifications if sent too fast.
        # A delay ensures the BLE queue flushes between chunks.
        await asyncio.sleep(0.2)

    def is_connected(self) -> bool:
        return self._connected

    def _on_read(self, characteristic, **kwargs) -> bytearray:
        """Handle read request on TX characteristic."""
        try:
            char_uuid = getattr(characteristic, "uuid", str(characteristic))
            char = self._server.get_characteristic(char_uuid)
            return char.value if char and char.value else bytearray(b"")
        except Exception:
            return bytearray(b"")

    def _on_write(self, characteristic, value, **kwargs) -> None:
        """Handle write to RX characteristic — peer sent us data."""
        data = bytes(value)
        char_uuid = getattr(characteristic, "uuid", str(characteristic)).split(":")[0].strip()

        if char_uuid.lower() == BLE_RX_CHAR_UUID.lower() and self._on_data:
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(
                    lambda d=data: asyncio.create_task(self._on_data(d))
                )
            else:
                logger.error("BLE peripheral received data but no active event loop.")
        else:
            logger.debug(f"_on_write: UUID mismatch or no callback")


class BLECentral(BaseTransport):
    """BLE Central using Bleak — scans for and connects to peripherals."""

    def __init__(self) -> None:
        super().__init__()
        self._client = None
        self._connected = False
        self._loop: asyncio.AbstractEventLoop | None = None

    async def scan(self, timeout: float = 10.0) -> list[dict]:
        """Scan for nearby Phantom Messenger peripherals.

        Returns a list of dicts with 'address', 'name', 'rssi'.
        """
        try:
            from bleak import BleakScanner  # type: ignore[import-untyped]
        except ImportError:
            logger.error(
                "bleak is not installed. Install it with: pip install bleak"
            )
            raise

        logger.info("Scanning for BLE devices (%ss)...", timeout)
        devices = await BleakScanner.discover(
            timeout=timeout, return_adv=True,
        )

        results = []
        for device, adv_data in devices.values():
            # Filter for devices advertising our service UUID
            uuids = [str(u).lower() for u in (adv_data.service_uuids or [])]
            if BLE_SERVICE_UUID.lower() in uuids:
                results.append({
                    "address": device.address,
                    "name": device.name or adv_data.local_name or "Unknown",
                    "rssi": adv_data.rssi,
                })

        logger.info("Found %d Phantom device(s).", len(results))
        return results

    async def start(self) -> None:
        """No-op for central — use connect_to() instead."""
        pass

    async def connect_to(self, address: str) -> bool:
        """Connect to a peripheral by address.

        Args:
            address: The Bluetooth address of the peripheral.

        Returns:
            True if connection was successful.
        """
        try:
            from bleak import BleakClient  # type: ignore[import-untyped]
        except ImportError:
            logger.error("bleak is not installed.")
            raise

        self._loop = asyncio.get_running_loop()
        self._client = BleakClient(
            address, disconnected_callback=self._handle_disconnect
        )

        try:
            await self._client.connect()
            self._connected = True
            
            # Explicitly await a short delay to ensure GATT table is ready on macOS
            try:
                # bleak automatically resolves services during connect() in recent versions,
                # but a tiny sleep helps macOS CoreBluetooth commit the GATT cache internally.
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.warning(f"Failed to settle GATT cache: {e}")

            logger.info("Connected to %s", address)

            # Subscribe to TX notifications (incoming data from peripheral)
            await self._client.start_notify(
                BLE_TX_CHAR_UUID, self._handle_notification
            )

            if self._on_connect:
                await self._on_connect()

            return True
        except Exception as exc:
            logger.error("Failed to connect to %s: %s", address, exc)
            self._connected = False
            return False

    async def stop(self) -> None:
        """Disconnect from the peripheral."""
        if self._client and self._client.is_connected:
            await self._client.disconnect()
        self._connected = False

    async def send(self, data: bytes) -> None:
        """Send data by writing to the peripheral's RX characteristic."""
        if self._client is None or not self._client.is_connected:
            raise RuntimeError("Not connected to any peripheral.")

        # Force response=True. macOS CoreBluetooth often silently drops "Write Without Response"
        # packets or fails to pass them to the `bless` server delegate.
        await self._client.write_gatt_char(BLE_RX_CHAR_UUID, data, response=True)

    def is_connected(self) -> bool:
        return self._connected

    def _handle_notification(self, sender, data: bytearray) -> None:
        """Handle incoming TX notification from the peripheral."""
        # Copy data immediately — the bytearray may be invalidated after this callback returns
        copied = bytes(data)
        logger.info(f"Central received notification: {len(copied)} bytes from {sender}")
        if self._on_data:
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(
                    lambda d=copied: asyncio.create_task(self._on_data(d))
                )
            else:
                logger.error("BLE central received data but no active event loop.")

    def _handle_disconnect(self, client) -> None:
        """Handle unexpected disconnection."""
        self._connected = False
        logger.warning("Disconnected from peripheral.")
        if self._on_disconnect:
            if self._loop and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(self._on_disconnect(), self._loop)
            else:
                logger.error("BLE central disconnected but no active event loop.")


# ---------------------------------------------------------------------------
# Loopback Transport (for single-machine testing)
# ---------------------------------------------------------------------------


class LoopbackTransport(BaseTransport):
    """In-memory loopback transport for testing without Bluetooth hardware.

    Create two instances and link them together::

        a = LoopbackTransport("Alice")
        b = LoopbackTransport("Bob")
        LoopbackTransport.link(a, b)
        await a.start()
        await b.start()
        await a.send(b"hello")  # b receives b"hello"
    """

    def __init__(self, name: str = "loopback") -> None:
        super().__init__()
        self._name = name
        self._peer: LoopbackTransport | None = None
        self._connected = False
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reader_task: asyncio.Task | None = None

    @staticmethod
    def link(a: "LoopbackTransport", b: "LoopbackTransport") -> None:
        """Link two loopback transports together."""
        a._peer = b
        b._peer = a

    async def start(self) -> None:
        self._connected = True
        self._reader_task = asyncio.create_task(self._read_loop())
        logger.info("Loopback transport '%s' started.", self._name)
        if self._on_connect:
            await self._on_connect()

    async def stop(self) -> None:
        self._connected = False
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._on_disconnect:
            await self._on_disconnect()

    async def send(self, data: bytes) -> None:
        if self._peer is None:
            raise RuntimeError("Loopback not linked to a peer.")
        await self._peer._queue.put(data)

    def is_connected(self) -> bool:
        return self._connected

    async def _read_loop(self) -> None:
        while self._connected:
            try:
                data = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                if self._on_data:
                    await self._on_data(data)
            except asyncio.TimeoutError:
                continue
