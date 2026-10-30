"""CoffreFichiers - service interne de stockage de fichiers chiffrés.

Lancement :  python -m app.app   (écoute sur http://127.0.0.1:5000)
"""

import os
import re

from flask import Flask, jsonify, request

from app.auth import generate_token, hash_password, verify_password, verify_token
from app.crypto_utils import decrypt_bytes, derive_user_key, encrypt_bytes
from app.sharing import generate_keypair, public_key_pem, unwrap_key, wrap_key

app = Flask(__name__)

# Tout est stocké en mémoire (perdu à l'arrêt du service).
USERS = {}    # username -> {"password_hash", "private_key", "public_key"}
STORAGE = {}  # file_id  -> {"owner", "filename", "blob"}
SHARES = {}   # (file_id, destinataire) -> {"wrapped_key", "blob"}

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")


def current_user():
    """Renvoie l'utilisateur authentifié par l'en-tête Authorization, ou None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    username = verify_token(token)
    if username not in USERS:
        return None
    return username


def error(message, status):
    return jsonify({"error": message}), status


# ---------------------------------------------------------------- comptes

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not USERNAME_RE.match(username) or len(password) < 8:
        return error("nom d'utilisateur ou mot de passe invalide", 400)
    if username in USERS:
        return error("utilisateur déjà existant", 409)

    private_key, public_key = generate_keypair()
    USERS[username] = {
        "password_hash": hash_password(password),
        "private_key": private_key,
        "public_key": public_key,
    }
    return jsonify({"message": f"compte {username} créé"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = USERS.get(username)
    if user is None or not verify_password(password, user["password_hash"]):
        return error("identifiants incorrects", 403)
    return jsonify({"token": generate_token(username)}), 200


@app.route("/pubkey/<username>", methods=["GET"])
def pubkey(username):
    user = USERS.get(username)
    if user is None:
        return error("utilisateur inconnu", 404)
    return jsonify({"username": username, "public_key": public_key_pem(user["public_key"])}), 200


# ---------------------------------------------------------------- fichiers

@app.route("/upload", methods=["POST"])
def upload():
    username = current_user()
    if username is None:
        return error("authentification requise", 401)

    f = request.files.get("file")
    if f is None:
        return error("aucun fichier", 400)

    key = derive_user_key(username)
    blob = encrypt_bytes(f.read(), key)

    file_id = f"file-{len(STORAGE) + 1}"
    STORAGE[file_id] = {"owner": username, "filename": f.filename, "blob": blob}
    return jsonify({"file_id": file_id, "len": len(blob)}), 201


@app.route("/files", methods=["GET"])
def list_files():
    username = current_user()
    if username is None:
        return error("authentification requise", 401)

    own = []
    for file_id, entry in STORAGE.items():
        if entry["owner"] == username:
            own.append({"file_id": file_id, "filename": entry["filename"]})

    shared = []
    for (file_id, recipient) in SHARES:
        if recipient == username:
            entry = STORAGE[file_id]
            shared.append({"file_id": file_id, "filename": entry["filename"], "owner": entry["owner"]})

    return jsonify({"own": own, "shared_with_me": shared}), 200


@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    username = current_user()
    if username is None:
        return error("authentification requise", 401)

    entry = STORAGE.get(file_id)
    if entry is None:
        return error("fichier introuvable", 404)

    if entry["owner"] == username:
        # Fichier personnel : déchiffré avec la clé de l'utilisateur
        key = derive_user_key(username)
        data = decrypt_bytes(entry["blob"], key)

    elif (file_id, username) in SHARES:
        # Fichier partagé : on récupère d'abord la clé de fichier avec RSA
        share = SHARES[(file_id, username)]
        file_key = unwrap_key(share["wrapped_key"], USERS[username]["private_key"])
        data = decrypt_bytes(share["blob"], file_key)

    else:
        return error("accès refusé", 403)

    return data, 200, {"Content-Type": "application/octet-stream"}


@app.route("/share/<file_id>", methods=["POST"])
def share(file_id):
    username = current_user()
    if username is None:
        return error("authentification requise", 401)

    entry = STORAGE.get(file_id)
    if entry is None or entry["owner"] != username:
        return error("fichier introuvable", 404)

    data = request.get_json(silent=True) or {}
    recipient = data.get("to", "")
    if recipient not in USERS or recipient == username:
        return error("destinataire invalide", 400)

    # 1. on déchiffre le fichier avec la clé du propriétaire
    plaintext = decrypt_bytes(entry["blob"], derive_user_key(username))

    # 2. on le rechiffre avec une clé de fichier aléatoire
    file_key = os.urandom(32)
    new_blob = encrypt_bytes(plaintext, file_key)

    # 3. on chiffre la clé de fichier pour le destinataire
    wrapped_key = wrap_key(file_key, USERS[recipient]["public_key"])

    SHARES[(file_id, recipient)] = {"wrapped_key": wrapped_key, "blob": new_blob}
    return jsonify({"message": f"{file_id} partagé avec {recipient}"}), 201


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
