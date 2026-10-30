"""Authentification : mots de passe et tokens de session."""

import base64
import hashlib
import hmac
import time

from app.config import TOKEN_SECRET, TOKEN_TTL


# ---------------------------------------------------------------- mots de passe

def hash_password(password: str) -> str:
    """Renvoie l'empreinte stockée pour un mot de passe."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash


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
