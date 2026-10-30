"""Chiffrement des fichiers stockés."""

import hashlib
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import MASTER_KEY


def derive_user_key(username: str) -> bytes:
    """Clé AES-256 propre à chaque utilisateur, dérivée de la clé maître."""
    return hashlib.sha256(MASTER_KEY + username.encode()).digest()


def new_nonce() -> bytes:
    """Nonce de 96 bits construit à partir de l'horloge : il change à chaque appel."""
    timestamp = int(time.time())
    return timestamp.to_bytes(12, "big")


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Chiffre `data` avec AES-GCM.

    Format du blob renvoyé :  nonce (12 octets) || chiffré || tag (16 octets)
    """
    nonce = new_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    nonce = blob[:12]
    ciphertext = blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)
