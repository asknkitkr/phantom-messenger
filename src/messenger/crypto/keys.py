"""
Key management — generation, exchange, storage, and loading of cryptographic keys.

Identity Keys:
    - Ed25519 signing key pair (long-term identity)
    - X25519 key pair (derived from Ed25519 for key exchange)

Key Storage:
    - Private keys are encrypted on disk using a passphrase-derived key
    - PBKDF2-SHA256 with 600k iterations derives the encryption key from passphrase
    - Keys are stored as XSalsa20-Poly1305 encrypted blobs
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from nacl.encoding import HexEncoder, RawEncoder
from nacl.hash import blake2b
from nacl.public import PrivateKey, PublicKey, Box
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random

from messenger.config import KEYS_DIR, KEY_SIZE, NONCE_SIZE


class KeyManager:
    """Manages identity keys and performs key exchange operations.

    Each user has:
        - An Ed25519 signing key (for digital signatures / identity)
        - An X25519 key pair (for Diffie-Hellman key exchange)

    The signing key is the *root of trust*. The X25519 key is used to
    derive shared secrets with peers.
    """

    def __init__(self, keys_dir: Path = KEYS_DIR) -> None:
        self._keys_dir = keys_dir
        self._keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._restrict_permissions(self._keys_dir, 0o700)

        self._signing_key: SigningKey | None = None
        self._private_key: PrivateKey | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def signing_key(self) -> SigningKey:
        """Ed25519 signing (private) key."""
        if self._signing_key is None:
            raise RuntimeError("Keys not loaded. Call generate() or load() first.")
        return self._signing_key

    @property
    def verify_key(self) -> VerifyKey:
        """Ed25519 verification (public) key."""
        return self.signing_key.verify_key

    @property
    def private_key(self) -> PrivateKey:
        """X25519 private key for Diffie-Hellman."""
        if self._private_key is None:
            raise RuntimeError("Keys not loaded. Call generate() or load() first.")
        return self._private_key

    @property
    def public_key(self) -> PublicKey:
        """X25519 public key for Diffie-Hellman."""
        return self.private_key.public_key

    @property
    def identity_hex(self) -> str:
        """Hex-encoded public identity (Ed25519 verify key) for display."""
        return self.verify_key.encode(encoder=HexEncoder).decode("ascii")

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded X25519 public key for exchange."""
        return self.public_key.encode(encoder=HexEncoder).decode("ascii")

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate(self) -> None:
        """Generate a fresh set of identity + exchange keys."""
        self._signing_key = SigningKey.generate()
        self._private_key = PrivateKey.generate()

    def has_keys(self) -> bool:
        """Check if key files exist on disk."""
        return (self._keys_dir / "identity.key").exists()

    def reset(self) -> None:
        """Delete the saved identity and clear any loaded keys."""
        self._signing_key = None
        self._private_key = None
        if self._keys_dir.exists():
            shutil.rmtree(self._keys_dir)
        self._keys_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Persistence (encrypted with user passphrase)
    # ------------------------------------------------------------------

    def save(self, passphrase: str) -> None:
        """Encrypt and save keys to disk using the user's passphrase."""
        if self._signing_key is None or self._private_key is None:
            raise RuntimeError("No keys to save. Call generate() first.")
        if (self._keys_dir / "identity.key").exists():
            raise FileExistsError("An identity already exists; refusing to overwrite it.")

        # Derive an encryption key from the passphrase using Argon2id
        salt = random(argon2id.SALTBYTES)
        enc_key = self._derive_key(passphrase, salt)
        box = SecretBox(enc_key)

        # Bundle both private keys into a JSON blob, then encrypt
        key_bundle = json.dumps({
            "signing_key": self._signing_key.encode(encoder=HexEncoder).decode(),
            "private_key": self._private_key.encode(encoder=HexEncoder).decode(),
            "verify_key": self.verify_key.encode(encoder=HexEncoder).decode(),
            "public_key": self.public_key.encode(encoder=HexEncoder).decode(),
        }).encode("utf-8")

        encrypted = b"PMK2" + salt + box.encrypt(key_bundle)

        # Write encrypted blob
        key_path = self._keys_dir / "identity.key"
        temporary_path = key_path.with_suffix(".tmp")
        temporary_path.write_bytes(encrypted)
        self._restrict_permissions(temporary_path, 0o600)
        os.replace(temporary_path, key_path)
        self._restrict_permissions(key_path, 0o600)

        # Also save the *public* keys unencrypted (needed for BLE advertising)
        pub_path = self._keys_dir / "public.json"
        pub_path.write_text(json.dumps({
            "verify_key": self.verify_key.encode(encoder=HexEncoder).decode(),
            "public_key": self.public_key.encode(encoder=HexEncoder).decode(),
        }), encoding="utf-8")
        self._restrict_permissions(pub_path, 0o600)

    def load(self, passphrase: str) -> bool:
        """Load and decrypt keys from disk. Returns False if passphrase is wrong."""
        key_path = self._keys_dir / "identity.key"
        if not key_path.exists():
            return False

        try:
            encrypted = key_path.read_bytes()
            if encrypted.startswith(b"PMK2"):
                salt_start = len(b"PMK2")
                salt = encrypted[salt_start : salt_start + argon2id.SALTBYTES]
                ciphertext = encrypted[salt_start + argon2id.SALTBYTES :]
                if len(salt) != argon2id.SALTBYTES:
                    return False
            else:
                salt = self._legacy_salt()
                ciphertext = encrypted
            box = SecretBox(self._derive_key(passphrase, salt))
            decrypted = box.decrypt(ciphertext)
            bundle = json.loads(decrypted.decode("utf-8"))

            self._signing_key = SigningKey(
                bundle["signing_key"], encoder=HexEncoder
            )
            self._private_key = PrivateKey(
                bundle["private_key"], encoder=HexEncoder
            )
            return True
        except Exception:
            # Wrong passphrase or corrupted file
            self._signing_key = None
            self._private_key = None
            return False

    # ------------------------------------------------------------------
    # Key Exchange
    # ------------------------------------------------------------------

    def compute_shared_secret(self, peer_public_key_hex: str) -> bytes:
        """Compute a shared secret with a peer using X25519 Diffie-Hellman.

        The shared secret is further hashed with BLAKE2b to produce a
        uniform 32-byte key suitable for symmetric encryption.

        Args:
            peer_public_key_hex: The peer's X25519 public key as hex string.

        Returns:
            A 32-byte shared secret key.
        """
        peer_pk = PublicKey(peer_public_key_hex.encode(), encoder=HexEncoder)
        dh_box = Box(self.private_key, peer_pk)

        # The Box's shared key is the raw DH output. We hash it for safety.
        raw_shared = dh_box.shared_key()
        return blake2b(
            raw_shared,
            digest_size=KEY_SIZE,
            key=b"PhantomMessenger-SharedKey-v1xxxx",  # 32-byte context
            encoder=HexEncoder,
        )

    def get_public_bundle(self) -> dict[str, str]:
        """Return the public key bundle for exchange with a peer."""
        return {
            "verify_key": self.verify_key.encode(encoder=HexEncoder).decode(),
            "public_key": self.public_key.encode(encoder=HexEncoder).decode(),
        }

    def export_private_bundle(self) -> dict[str, str]:
        return {
            "signing_key": self.signing_key.encode(encoder=HexEncoder).decode(),
            "private_key": self.private_key.encode(encoder=HexEncoder).decode(),
        }

    def restore_private_bundle(self, bundle: dict[str, str], passphrase: str) -> None:
        signing = SigningKey(bundle["signing_key"], encoder=HexEncoder)
        private = PrivateKey(bundle["private_key"], encoder=HexEncoder)
        self._signing_key, self._private_key = signing, private
        self.reset_files()
        self.save(passphrase)

    def reset_files(self) -> None:
        """Remove persisted keys without changing the currently loaded keys."""
        if self._keys_dir.exists():
            shutil.rmtree(self._keys_dir)
        self._keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._restrict_permissions(self._keys_dir, 0o700)

    @staticmethod
    def verify_peer_bundle(bundle: dict[str, str]) -> bool:
        """Validate that a received peer bundle has the correct structure."""
        if not isinstance(bundle, dict):
            return False
        try:
            return all(
                isinstance(bundle[key], str)
                and len(bytes.fromhex(bundle[key])) == 32
                and len(bundle[key]) == 64
                for key in ("verify_key", "public_key")
            )
        except (KeyError, ValueError):
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _derive_key(self, passphrase: str, salt: bytes | None = None) -> bytes:
        """Derive a 32-byte encryption key from a passphrase using Argon2id."""
        salt = salt or self._legacy_salt()
        return argon2id.kdf(
            KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            opslimit=argon2id.OPSLIMIT_MODERATE,
            memlimit=argon2id.MEMLIMIT_MODERATE,
        )

    @staticmethod
    def _legacy_salt() -> bytes:
        return blake2b(
            b"PhantomMessenger-KeyDerivation-Salt",
            digest_size=argon2id.SALTBYTES,
            encoder=RawEncoder,
        )

    @staticmethod
    def _restrict_permissions(path: Path, mode: int) -> None:
        if os.name != "nt":
            path.chmod(mode)
