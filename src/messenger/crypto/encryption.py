"""
Message encryption & decryption — end-to-end encrypted messaging.

Uses XSalsa20-Poly1305 authenticated encryption (via NaCl SecretBox)
with Ed25519 signatures for sender authentication.

Wire format of an encrypted message:
    [nonce: 24 bytes][ciphertext + MAC: variable][signature: 64 bytes]
"""

from __future__ import annotations

import struct
import time

from nacl.encoding import HexEncoder, RawEncoder
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random
from nacl.exceptions import BadSignatureError, CryptoError

from messenger.config import NONCE_SIZE


class MessageEncryptor:
    """Encrypts and decrypts messages using a shared secret, with Ed25519 signing.

    Each message is:
        1. Serialised to bytes with a timestamp
        2. Encrypted with XSalsa20-Poly1305 using the shared secret
        3. Signed with the sender's Ed25519 key

    The recipient:
        1. Verifies the Ed25519 signature
        2. Decrypts the ciphertext
        3. Extracts the plaintext and timestamp
    """

    # Internal message envelope: [timestamp:8 bytes (double)][text (utf-8)]
    _TIMESTAMP_FORMAT = ">d"  # big-endian double (8 bytes)
    _TIMESTAMP_SIZE = struct.calcsize(_TIMESTAMP_FORMAT)
    _SIGNATURE_SIZE = 64  # Ed25519 signature is always 64 bytes

    def __init__(
        self,
        shared_secret: bytes,
        signing_key: SigningKey,
    ) -> None:
        """
        Args:
            shared_secret: 32-byte shared secret from X25519 key exchange.
                           May be hex-encoded bytes from KeyManager.compute_shared_secret.
            signing_key: The local user's Ed25519 signing key.
        """
        # shared_secret might be hex-encoded from blake2b — decode if needed
        if len(shared_secret) == 64:
            key_bytes = bytes.fromhex(shared_secret.decode() if isinstance(shared_secret, bytes) else shared_secret)
        elif len(shared_secret) == 32:
            key_bytes = shared_secret if isinstance(shared_secret, bytes) else bytes.fromhex(shared_secret)
        else:
            raise ValueError(f"Invalid shared secret length: {len(shared_secret)}")

        self._box = SecretBox(key_bytes)
        self._signing_key = signing_key

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a text message and sign it.

        Args:
            plaintext: The message text to encrypt.

        Returns:
            Encrypted + signed wire-format bytes:
            [nonce(24)][ciphertext+MAC][signature(64)]
        """
        # Build the inner envelope: timestamp + text
        timestamp = time.time()
        envelope = struct.pack(self._TIMESTAMP_FORMAT, timestamp) + plaintext.encode("utf-8")

        # Encrypt with a random nonce
        nonce = random(NONCE_SIZE)
        encrypted = self._box.encrypt(envelope, nonce=nonce)
        # `encrypted` already contains: nonce(24) + ciphertext + MAC(16)

        # Sign the entire encrypted blob
        signed = self._signing_key.sign(encrypted)
        # `signed` contains: signature(64) + encrypted
        # We rearrange to: encrypted + signature for clarity
        signature = signed.signature
        return encrypted + signature

    def decrypt(
        self,
        data: bytes,
        sender_verify_key: VerifyKey,
    ) -> tuple[str, float]:
        """Decrypt and verify a received message.

        Args:
            data: The raw wire-format bytes received from the peer.
            sender_verify_key: The sender's Ed25519 public verification key.

        Returns:
            A tuple of (plaintext, timestamp).

        Raises:
            BadSignatureError: If the signature doesn't match.
            CryptoError: If decryption fails (wrong key or tampered data).
            ValueError: If the message format is invalid.
        """
        if len(data) < NONCE_SIZE + 16 + self._SIGNATURE_SIZE:
            raise ValueError("Message too short to be valid")

        # Split encrypted blob and signature
        encrypted = data[: -self._SIGNATURE_SIZE]
        signature = data[-self._SIGNATURE_SIZE :]

        # Verify the Ed25519 signature over the encrypted blob
        sender_verify_key.verify(encrypted, signature)

        # Decrypt
        decrypted = self._box.decrypt(encrypted)

        # Unpack the inner envelope
        if len(decrypted) < self._TIMESTAMP_SIZE:
            raise ValueError("Decrypted envelope too short")

        timestamp = struct.unpack(
            self._TIMESTAMP_FORMAT,
            decrypted[: self._TIMESTAMP_SIZE],
        )[0]
        plaintext = decrypted[self._TIMESTAMP_SIZE :].decode("utf-8")

        return plaintext, timestamp

    @staticmethod
    def is_valid_text(text: str) -> bool:
        """Validate that text contains only printable ASCII/Unicode text — no emoji.

        This enforces the text-only policy:
            - Only printable characters (letters, digits, punctuation, spaces)
            - Newlines and tabs are allowed
            - No emoji or special Unicode symbols
        """
        for ch in text:
            cp = ord(ch)
            # Allow: tab, newline, carriage return, and printable ASCII+Latin
            if cp in (0x09, 0x0A, 0x0D):
                continue
            if 0x20 <= cp <= 0x007E:  # Basic ASCII printable
                continue
            if 0x00A0 <= cp <= 0x024F:  # Latin Extended
                continue
            if 0x2000 <= cp <= 0x206F:  # General punctuation
                continue
            # Block everything else (emoji, symbols, CJK, etc.)
            return False
        return True
