"""Authentification : mots de passe et tokens de session."""

import base64
import hashlib
import hmac
import os
import time

from app.config import TOKEN_SECRET, TOKEN_TTL


# ---------------------------------------------------------------- mots de passe

def _derive(password: str, salt: bytes) -> bytes:
    """Calcule l'empreinte PBKDF2-HMAC-SHA256 à partir d'un mot de passe et d'un sel."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def hash_password(password: str) -> str:
    """Tire un sel de 16 octets et renvoie (sel || empreinte) en base64."""
    salt = os.urandom(16)
    digest = _derive(password, salt)
    return base64.b64encode(salt + digest).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    """Récupère les 16 premiers octets (le sel) et compare l'empreinte."""
    raw = base64.b64decode(stored_hash)
    salt = raw[:16]
    expected_digest = raw[16:]
    return hmac.compare_digest(_derive(password, salt), expected_digest)

# ---------------------------------------------------------------------- tokens
# Un token a la forme :   base64("<username>|<expiration>") . signature
# La signature est un HMAC-SHA256 du contenu, en hexadécimal.

def sign(payload: bytes) -> str:
    return hmac.new(TOKEN_SECRET, payload, hashlib.sha256).hexdigest()


def generate_token(username: str) -> str:
    expiration = int(time.time()) + TOKEN_TTL
    payload = f"{username}|{expiration}".encode()
    encoded = base64.urlsafe_b64encode(payload).decode()
    return encoded + "." + sign(payload)


def verify_token(token: str):
    """Renvoie le nom d'utilisateur si le token est valide, None sinon."""
    try:
        encoded, signature = token.split(".")
        payload = base64.urlsafe_b64decode(encoded)
        username, expiration = payload.decode().rsplit("|", 1)
    except ValueError:
        return None  # token mal formé

    if signature != sign(payload):
        return None

    # L'expiration est conservée dans le token pour un usage futur.
    return username
