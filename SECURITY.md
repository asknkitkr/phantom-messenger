# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Phantom Messenger, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer directly with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
3. Allow up to 72 hours for an initial response

## Security Architecture

Phantom Messenger uses the following cryptographic primitives:

| Component | Algorithm | Library |
|-----------|-----------|---------|
| Key Exchange | X25519 (Curve25519 DH) | PyNaCl (libsodium) |
| Message Encryption | XSalsa20-Poly1305 | PyNaCl (libsodium) |
| Message Signing | Ed25519 | PyNaCl (libsodium) |
| Key Derivation | Argon2id | PyNaCl (libsodium) |
| Database Encryption | AES-256-CBC | SQLCipher |

All cryptographic operations use the well-audited **libsodium** library via PyNaCl bindings. No custom cryptography is implemented.
