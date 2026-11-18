import base64
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from app.auth import sign, verify_token as verify_token_corrige
from app.config import TOKEN_TTL


def verify_token_vulnerable(token: str):
    """Copie de app/auth.py d'origine (lignes 33 à 44)."""
    try:
        encoded, signature = token.split(".")
        payload = base64.urlsafe_b64decode(encoded)
        username, expiration = payload.decode().rsplit("|", 1)
    except ValueError:
        return None

    if signature != sign(payload):
        return None

    # L'expiration est conservée dans le token pour un usage futur.
    return username


# 1. Création d'un jeton déjà expiré (il y a 1 heure)
victime = "alice"
maintenant = int(time.time())
expiration_passee = maintenant - 3600

payload = f"{victime}|{expiration_passee}".encode()
encoded = base64.urlsafe_b64encode(payload).decode()
token_expire = f"{encoded}.{sign(payload)}"

print("=== 1. Jeton forgé (déjà expiré) ===")
print(f"Compte ciblé       : {victime}")
print(f"Expiration du token: {expiration_passee} (expiré depuis {maintenant - expiration_passee}s, TTL prévu = {TOKEN_TTL}s)")
print(f"Jeton généré       : {token_expire}\n")

# 2. Test sur la fonction d'origine (vulnérable)
print("=== 2. Comportement du code audité (vulnérable) ===")
res_vuln = verify_token_vulnerable(token_expire)
print(f"Retour de verify_token() : {res_vuln!r}")
if res_vuln == victime:
    print("-> FAILLE CONFIRMÉE : le jeton périmé est accepté indéfiniment.\n")