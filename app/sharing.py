"""Partage de fichiers entre utilisateurs à l'aide de RSA.

Lorsqu'un fichier est partagé, il est rechiffré avec une clé de fichier
aléatoire ; cette clé est ensuite chiffrée avec la clé publique RSA du
destinataire.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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
    return public_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def unwrap_key(wrapped: bytes, private_key) -> bytes:
    """Déchiffre une clé de fichier avec la clé privée RSA (OAEP)."""
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
