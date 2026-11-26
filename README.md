# Phantom Messenger

Private messages over Bluetooth LE. No internet connection required.

Phantom Messenger lets nearby devices exchange encrypted text messages over Bluetooth Low Energy (BLE). It works without an internet or cellular connection.

> [!NOTE]
> It can be useful when internet access is unavailable or when you want to message someone nearby without using a network.

## Features

- **Works offline:** devices communicate directly over Bluetooth LE.
- **Private messages:** messages are encrypted and signed using libsodium.
- **Encrypted storage:** SQLCipher protects locally stored messages and contacts.
- **Runs on Windows, macOS, and Linux:** Bluetooth support depends on the operating system and adapter.
- **Text only:** messages cannot include images or attachments; emoji and some special characters are not supported.
- **Passphrase protected:** identity keys are encrypted with a key derived using Argon2id.
- **Terminal app:** the interface is built with [Textual](https://textual.textualize.io/).

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 Terminal UI (Textual)            │
├─────────────────────────────────────────────────┤
│              Application Layer                  │
│         (Conversations, Contacts)               │
├──────────────────────┬──────────────────────────┤
│   Crypto Layer       │    Storage Layer         │
│  (PyNaCl/libsodium)  │    (SQLCipher)           │
│  X25519 + XSalsa20   │    AES-256-CBC           │
│  + Ed25519           │                          │
├──────────────────────┴──────────────────────────┤
│            BLE Transport Layer                  │
│           (Bleak + Bless)                       │
│    ┌─────────────┐  ┌──────────────┐            │
│    │ Peripheral   │  │   Central    │            │
│    │ (Advertise)  │  │ (Scan+Connect)│           │
│    └─────────────┘  └──────────────┘            │
└─────────────────────────────────────────────────┘
         ↕ Bluetooth Low Energy
```

### How It Works

1. **Device A** starts advertising as a BLE Peripheral (GATT server)
2. **Device B** scans for nearby Phantom devices as a BLE Central
3. The devices exchange their X25519 and Ed25519 public keys over BLE.
4. Each device derives the same shared secret locally using X25519; the secret is never sent.
5. Messages are encrypted, signed, split into BLE packets, and sent over GATT.
6. Contacts and messages are stored in the encrypted SQLCipher database.

### BLE Transport Protocol

Messages are split into chunks sized for the negotiated BLE connection:

```
Chunk format (11-byte header + payload):
[type: 1 byte][transfer ID: 4 bytes][sequence: 2 bytes]
[total chunks: 2 bytes][payload length: 2 bytes][payload]

Message types:
  0x01 = KEY_EXCHANGE    (public key bundle as JSON)
  0x02 = TEXT_MESSAGE    (encrypted + signed payload)
  0x03 = ACK             (delivery acknowledgment)
```

### Encrypted Message Wire Format

```
[nonce: 24 bytes][ciphertext + MAC: variable][signature: 64 bytes]
```

## Security Model

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | X25519 (Curve25519 DH) | Compute shared secret between peers |
| Message Encryption | XSalsa20-Poly1305 | Authenticated encryption of messages |
| Message Signing | Ed25519 | Verify sender identity, prevent tampering |
| Key Storage | Argon2id + XSalsa20-Poly1305 | Encrypt private keys with user passphrase |
| Database | AES-256-CBC (SQLCipher) | Encrypt all stored messages at rest |

All cryptographic operations use the well-audited **[libsodium](https://libsodium.org/)** library via [PyNaCl](https://pynacl.readthedocs.io/) bindings. No custom cryptography is implemented.

## Quick Start

### One-Command Setup (Recommended)

```bash
git clone https://github.com/YOUR_USERNAME/phantom-messenger.git
cd phantom-messenger
chmod +x run.sh
./run.sh
```

This will automatically:
1. Detect your OS (macOS, Linux, Windows/WSL)
2. Install system dependencies (Python 3.11+, libsodium, SQLCipher)
3. Create a virtual environment and install the project
4. Launch the app

```bash
./run.sh --install   # Set up only (don't launch)
./run.sh --test      # Set up and run tests only
./run.sh --clean     # Wipe data and start fresh
./run.sh --help      # Show all options
```

### Manual Installation

#### Prerequisites

- Python 3.11 or higher
- A Bluetooth adapter (built-in or USB)
- For encrypted database: SQLCipher library (`brew install sqlcipher` on macOS)

#### Install

```bash
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Running

```bash
# Default mode — no BLE, manual key exchange only
python -m messenger

# BLE Peripheral mode (advertise your device)
python -m messenger --mode peripheral

# BLE Central mode (scan and connect to devices)
python -m messenger --mode central

# Loopback mode (testing on a single machine)
python -m messenger --mode loopback

# With debug logging (writes to phantom.log)
python -m messenger --debug
```

## Usage Guide

### First Time Setup

1. Run the app: `./run.sh` or `python -m messenger`
2. Enter a strong passphrase (12+ characters) — this encrypts your keys and database
3. Click **Create Identity** and enter the passphrase twice to confirm it
4. Press **Ctrl+K** to view and copy your key bundle.

### Connecting Two Devices

**Via BLE (both users nearby):**

| Device A (Advertiser) | Device B (Scanner) |
|---|---|
| `./run.sh` → Log in | `./run.sh` → Log in |
| Click **Advertise** | Click **+ Scan** |
| Wait for connection... | Select Device A from list |
| A verification code appears for the new contact. | Compare the code with the other device through a trusted channel, then choose **Trust Contact**. |
| Compare the same code and choose **Trust Contact**. | The verified contact appears in the sidebar. |

**Via Manual Key Exchange:**

1. Both users: Press **Ctrl+K** and copy your key bundle
2. Exchange bundles out of band (for example, in person or through another trusted channel)
3. Press **Ctrl+N** → **Add Manual** and paste the other person's JSON bundle

### Sending Messages

1. Select a contact from the sidebar
2. Type your message in the input bar
3. Press **Enter** or click **Send**
4. Messages must be plain text. Emoji and some special characters are not supported.

## Key Bindings

| Key | Action |
|-----|--------|
| `Ctrl+N` | Scan for nearby devices |
| `Ctrl+A` | Start advertising |
| `Ctrl+K` | Show and copy your key bundle |
| `Ctrl+M` | Toggle compact mode |
| `Ctrl+H` | Show keyboard help |
| `Ctrl+Q` | Quit |
| `Enter` | Send message |
| `Escape` | Close dialog/go back |

The **Tools** menu contains contact rename/removal, message retry, conversation export,
encrypted profile backup/restore, connection controls, and keyboard help. Search contacts
and message text from the sidebar. Select **Load older messages** to page through history.
Backups include the identity and local conversations; keep the separate backup password safe.

## Project Structure

```
phantom-messenger/
├── run.sh                 # Universal setup & run script
├── pyproject.toml         # Project metadata & dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── CONTRIBUTING.md        # Contributor guide
├── SECURITY.md            # Security policy
├── tests/                 # Test suite
└── src/messenger/
    ├── __init__.py
    ├── __main__.py        # Entry point & CLI argument parsing
    ├── config.py          # All configuration constants
    ├── crypto/
    │   ├── keys.py        # KeyManager: X25519/Ed25519 key generation,
    │   │                  #   storage, loading, shared secret computation
    │   └── encryption.py  # MessageEncryptor: XSalsa20-Poly1305 encrypt/
    │                      #   decrypt with Ed25519 signing & verification
    ├── storage/
    │   ├── models.py      # Dataclasses: Contact, Message, Conversation
    │   └── database.py    # DatabaseManager: SQLCipher encrypted storage
    │                      #   for contacts and messages
    ├── transport/
    │   ├── protocol.py    # Chunk/ChunkAssembler: BLE message framing,
    │   │                  #   splitting, and reassembly
    │   └── peripheral.py  # BLEPeripheral (GATT server via Bless),
    │                      #   BLECentral (scanner/connector via Bleak),
    │                      #   LoopbackTransport (testing)
    └── ui/
        └── app.py         # Full Textual TUI: LoginScreen, MainScreen,
                           #   ScanScreen, ManualAddScreen + PhantomApp
```

## Configuration

All configuration is in [`src/messenger/config.py`](src/messenger/config.py):

| Constant | Value | Description |
|----------|-------|-------------|
| `BLE_MAX_PACKET_SIZE` | 120 | Maximum protocol frame size before negotiated MTU limits |
| `BLE_SCAN_TIMEOUT` | 10s | How long to scan for devices |
| `MAX_MESSAGE_LENGTH` | 10,000 | Max characters per message |
| `PBKDF2_ITERATIONS` | 600,000 | Key derivation iterations (OWASP recommended) |
| `SQLCIPHER_KDF_ITER` | 256,000 | Database encryption iterations |

## Platform Notes

### macOS
- Grant Bluetooth access: **System Settings → Privacy & Security → Bluetooth**
- Bleak's supported baseline is macOS 10.15+; this app has been tested on macOS 12+ only
- Uses CoreBluetooth via Bless/Bleak

### Linux
- Add your user to the `bluetooth` group: `sudo usermod -aG bluetooth $USER`
- BlueZ 5.55+ required by the current Bleak baseline
- May need `sudo` for BLE advertising

### Windows
- Bleak's current tested baseline is Windows 11 (build 22000+) with Bluetooth support
- Grant Bluetooth access if prompted by Windows Security
- Bless installs its Windows BLE backend dependencies with the project

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=messenger
```

## License

[MIT](LICENSE) — see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
