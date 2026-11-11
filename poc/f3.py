import io
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
from app.app import app, STORAGE

client = app.test_client()

# 1. Enregistrement et connexion d’un utilisateur

client.post("/register", json={"username": "bob", "password": "motdepassse-bob"})
token = client.post("/login", json={"username": "bob", "password": "motdepassse-bob"}).get_json()["token"]
auth = {"Authorization": f"Bearer {token}"}

# 2. Upload simultané de deux fichiers dans la même seconde

clair1 = b"SECRET_CONFIDENTIEL_NUMERO_1"
clair2 = b"SECRET_CONFIDENTIEL_NUMERO_2"

r1 = client.post("/upload", headers=auth,content_type="multipart/form-data",data={"file": (io.BytesIO(clair1), "f1.txt")})
r2 = client.post("/upload", headers=auth,content_type="multipart/form-data",data={"file": (io.BytesIO(clair2), "f2.txt")})

id1, id2 = r1.get_json()["file_id"], r2.get_json()["file_id"]
blob1 = STORAGE[id1]["blob"]
blob2 = STORAGE[id2]["blob"]

nonce1, c1 = blob1[:12], blob1[12:-16]
nonce2, c2 = blob2[:12], blob2[12:-16]

print(f"[+] Nonce 1 : {nonce1.hex()}")
print(f"[+] Nonce 2 : {nonce2.hex()}")

if nonce1 != nonce2:
    print("[-] Echec : les nonces sont differents.")