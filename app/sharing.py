"""Partage de fichiers entre utilisateurs à l'aide de RSA.

Lorsqu'un fichier est partagé, il est rechiffré avec une clé de fichier
aléatoire ; cette clé est ensuite chiffrée avec la clé publique RSA du
destinataire.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import RSA_KEY_SIZE, RSA_PUBLIC_EXPONENT


def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )
    return private_key, private_key.public_key()


def public_key_pem(public_key) -> str:
    """Clé publique au format PEM, pour l'endpoint /pubkey."""
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode()


def wrap_key(file_key: bytes, public_key) -> bytes:
    """Chiffre une clé de fichier (32 octets) avec la clé publique RSA."""
    n = public_key.public_numbers().n
    e = public_key.public_numbers().e

    m = int.from_bytes(file_key, "big")
    c = pow(m, e, n)  # c = m^e mod n
    return c.to_bytes(public_key.key_size // 8, "big")


def unwrap_key(wrapped: bytes, private_key) -> bytes:
    """Déchiffre une clé de fichier avec la clé privée RSA."""
    n = private_key.public_key().public_numbers().n
    d = private_key.private_numbers().d

    c = int.from_bytes(wrapped, "big")
    m = pow(c, d, n)  # m = c^d mod n
    return m.to_bytes(32, "big")
