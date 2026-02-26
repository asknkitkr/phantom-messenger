# Contributing to Phantom Messenger

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/phantom-messenger.git
cd phantom-messenger

# One-command setup
chmod +x run.sh
./run.sh --install

# Or manual setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Project Structure

```
src/messenger/
├── __main__.py           # Entry point & CLI
├── config.py             # Configuration constants
├── crypto/
│   ├── keys.py           # Key generation & exchange (X25519, Ed25519)
│   └── encryption.py     # Message encrypt/decrypt (XSalsa20-Poly1305)
├── storage/
│   ├── models.py         # Data models (Contact, Message, Conversation)
│   └── database.py       # SQLCipher encrypted database
├── transport/
│   ├── protocol.py       # Message framing & chunking protocol
│   └── peripheral.py     # BLE transport (Peripheral + Central)
└── ui/
    └── app.py            # Terminal UI (Textual framework)
```

## Code Style

- Follow PEP 8 with 100-char line width
- Use type hints throughout
- Docstrings for all public functions and classes
- Use `logger` (not `print()`) for operational output

## Submitting Changes

1. Fork the repo and create a feature branch
2. Make your changes with clear commit messages
3. Ensure tests pass: `python -m pytest tests/ -v`
4. Open a Pull Request with a description of what changed and why

## Security

If you discover a security vulnerability, please do **not** open a public issue. Instead, email the maintainer directly.
