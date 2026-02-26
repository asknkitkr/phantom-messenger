"""Application configuration constants."""

import os
import platform
from pathlib import Path

# ---------------------------------------------------------------------------
# Application Identity
# ---------------------------------------------------------------------------
APP_NAME = "PhantomMessenger"
APP_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Data Directories (platform-specific)
# ---------------------------------------------------------------------------
_system = platform.system()

if _system == "Windows":
    _base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
elif _system == "Darwin":
    _base = Path.home() / "Library" / "Application Support"
else:
    _base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))

DATA_DIR: Path = _base / APP_NAME
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH: Path = DATA_DIR / "phantom.db"
KEYS_DIR: Path = DATA_DIR / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Bluetooth LE — Custom GATT Service & Characteristic UUIDs
# ---------------------------------------------------------------------------
# Generated once, unique to this application
BLE_SERVICE_UUID = "7e5c4a3b-2d1e-0f9a-8b7c-6d5e4f3a2b1c"
BLE_TX_CHAR_UUID = "7e5c4a3b-2d1e-0f9a-8b7c-6d5e4f3a2b1d"  # Notify (server → client)
BLE_RX_CHAR_UUID = "7e5c4a3b-2d1e-0f9a-8b7c-6d5e4f3a2b1e"  # Write  (client → server)

BLE_DEVICE_NAME = "Phantom"
BLE_SCAN_TIMEOUT = 10.0  # seconds
BLE_MTU = 120  # Safe MTU for macOS Write Without Response (can drop if >128)

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum for PBKDF2-SHA256
NONCE_SIZE = 24  # XSalsa20 nonce size in bytes
KEY_SIZE = 32  # X25519 / XSalsa20 key size in bytes

# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------
HEADER_SIZE = 7  # msg_type(1) + seq(2) + total(2) + payload_len(2)
MAX_MESSAGE_LENGTH = 10_000  # characters, prevents abuse
MAX_CHUNK_PAYLOAD = BLE_MTU - HEADER_SIZE

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
SQLCIPHER_KDF_ITER = 256_000  # SQLCipher PBKDF2 iterations for DB key
