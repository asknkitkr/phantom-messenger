"""Passphrase-encrypted profile backup container."""

from __future__ import annotations

import json

from nacl.pwhash import argon2id
from nacl.secret import SecretBox
from nacl.utils import random

_MAGIC = b"PHB1"


def encrypt_backup(data: dict, passphrase: str) -> bytes:
    salt = random(argon2id.SALTBYTES)
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )
    return _MAGIC + salt + SecretBox(key).encrypt(json.dumps(data).encode("utf-8"))


def decrypt_backup(blob: bytes, passphrase: str) -> dict:
    if not blob.startswith(_MAGIC) or len(blob) < len(_MAGIC) + argon2id.SALTBYTES + SecretBox.NONCE_SIZE + SecretBox.MACBYTES:
        raise ValueError("Not a valid Phantom backup")
    start = len(_MAGIC)
    salt = blob[start : start + argon2id.SALTBYTES]
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )
    return json.loads(SecretBox(key).decrypt(blob[start + argon2id.SALTBYTES :]).decode("utf-8"))
