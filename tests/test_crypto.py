"""Unit tests for the cryptographic module."""

import pytest
from messenger.crypto.keys import KeyManager
from messenger.crypto.encryption import MessageEncryptor

from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder


class TestKeyManager:
    """Tests for key generation, storage, and exchange."""

    def test_generate_creates_keys(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path / "keys")
        km.generate()

        assert km.signing_key is not None
        assert km.verify_key is not None
        assert km.private_key is not None
        assert km.public_key is not None

    def test_identity_hex_is_64_chars(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path / "keys")
        km.generate()
        assert len(km.identity_hex) == 64
        assert len(km.public_key_hex) == 64

    def test_save_and_load(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path / "keys")
        km.generate()
        original_identity = km.identity_hex
        original_pubkey = km.public_key_hex
        km.save("test_passphrase_123")

        # Load in a new instance
        km2 = KeyManager(keys_dir=tmp_path / "keys")
        assert km2.load("test_passphrase_123") is True
        assert km2.identity_hex == original_identity
        assert km2.public_key_hex == original_pubkey

    def test_load_wrong_passphrase(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path / "keys")
        km.generate()
        km.save("correct_passphrase")

        km2 = KeyManager(keys_dir=tmp_path / "keys")
        assert km2.load("wrong_passphrase") is False

    def test_load_no_keys(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path / "keys")
        assert km.load("anything") is False

    def test_has_keys(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path / "keys")
        assert km.has_keys() is False
        km.generate()
        km.save("pass")
        assert km.has_keys() is True

    def test_shared_secret_agreement(self, tmp_path):
        """Two parties compute the same shared secret."""
        alice = KeyManager(keys_dir=tmp_path / "alice")
        bob = KeyManager(keys_dir=tmp_path / "bob")
        alice.generate()
        bob.generate()

        secret_a = alice.compute_shared_secret(bob.public_key_hex)
        secret_b = bob.compute_shared_secret(alice.public_key_hex)
        assert secret_a == secret_b

    def test_public_bundle_format(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path / "keys")
        km.generate()
        bundle = km.get_public_bundle()
        assert "verify_key" in bundle
        assert "public_key" in bundle
        assert len(bundle["verify_key"]) == 64
        assert len(bundle["public_key"]) == 64

    def test_verify_peer_bundle_valid(self):
        assert KeyManager.verify_peer_bundle({
            "verify_key": "a" * 64,
            "public_key": "b" * 64,
        }) is True

    def test_verify_peer_bundle_invalid(self):
        assert KeyManager.verify_peer_bundle({"verify_key": "short"}) is False
        assert KeyManager.verify_peer_bundle({}) is False
        assert KeyManager.verify_peer_bundle("not a dict") is False


class TestMessageEncryptor:
    """Tests for message encryption and decryption."""

    @pytest.fixture
    def alice_bob(self, tmp_path):
        """Create two key managers and their encryptors."""
        alice_km = KeyManager(keys_dir=tmp_path / "alice")
        bob_km = KeyManager(keys_dir=tmp_path / "bob")
        alice_km.generate()
        bob_km.generate()

        shared_a = alice_km.compute_shared_secret(bob_km.public_key_hex)
        shared_b = bob_km.compute_shared_secret(alice_km.public_key_hex)

        enc_a = MessageEncryptor(shared_a, alice_km.signing_key)
        enc_b = MessageEncryptor(shared_b, bob_km.signing_key)

        return alice_km, bob_km, enc_a, enc_b

    def test_encrypt_decrypt_roundtrip(self, alice_bob):
        alice_km, bob_km, enc_a, enc_b = alice_bob

        original = "Hello, Bob! This is a secret message."
        encrypted = enc_a.encrypt(original)

        # Bob decrypts using Alice's verify key
        alice_vk = VerifyKey(alice_km.identity_hex.encode(), encoder=HexEncoder)
        plaintext, timestamp = enc_b.decrypt(encrypted, alice_vk)

        assert plaintext == original
        assert timestamp > 0

    def test_different_messages_different_ciphertext(self, alice_bob):
        _, _, enc_a, _ = alice_bob
        ct1 = enc_a.encrypt("message one")
        ct2 = enc_a.encrypt("message two")
        assert ct1 != ct2

    def test_same_message_different_nonce(self, alice_bob):
        _, _, enc_a, _ = alice_bob
        ct1 = enc_a.encrypt("same message")
        ct2 = enc_a.encrypt("same message")
        # Different nonces means different ciphertext
        assert ct1 != ct2

    def test_tampered_message_fails(self, alice_bob):
        alice_km, _, enc_a, enc_b = alice_bob
        encrypted = enc_a.encrypt("sensitive data")

        # Tamper with a byte in the middle
        tampered = bytearray(encrypted)
        tampered[len(tampered) // 2] ^= 0xFF
        tampered = bytes(tampered)

        alice_vk = VerifyKey(alice_km.identity_hex.encode(), encoder=HexEncoder)
        with pytest.raises(Exception):
            enc_b.decrypt(tampered, alice_vk)

    def test_wrong_sender_key_fails(self, alice_bob, tmp_path):
        alice_km, bob_km, enc_a, enc_b = alice_bob

        encrypted = enc_a.encrypt("from alice")

        # Try to verify with a random key (not Alice's)
        fake_km = KeyManager(keys_dir=tmp_path / "fake")
        fake_km.generate()
        fake_vk = VerifyKey(fake_km.identity_hex.encode(), encoder=HexEncoder)

        with pytest.raises(Exception):
            enc_b.decrypt(encrypted, fake_vk)

    def test_too_short_message_raises(self, alice_bob):
        alice_km, _, _, enc_b = alice_bob
        alice_vk = VerifyKey(alice_km.identity_hex.encode(), encoder=HexEncoder)
        with pytest.raises(ValueError, match="too short"):
            enc_b.decrypt(b"short", alice_vk)

    def test_is_valid_text_allows_ascii(self):
        assert MessageEncryptor.is_valid_text("Hello, World!") is True
        assert MessageEncryptor.is_valid_text("123 + 456 = 579") is True
        assert MessageEncryptor.is_valid_text("line1\nline2\ttab") is True

    def test_is_valid_text_blocks_emoji(self):
        assert MessageEncryptor.is_valid_text("Hello 😀") is False
        assert MessageEncryptor.is_valid_text("🔥") is False

    def test_is_valid_text_empty(self):
        assert MessageEncryptor.is_valid_text("") is True
