import os
import sys
from pathlib import Path

# Ajout de la racine du projet au PATH
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from app.crypto_utils import decrypt_bytes, encrypt_bytes
from app.sharing import generate_keypair, wrap_key


def integer_cbrt(n: int) -> int:
    """Racine cubique entière exacte sur grands entiers."""
    low, high = 1, 1 << ((n.bit_length() + 2) // 3)
    while low < high:
        mid = (low + high + 1) // 2
        if mid**3 <= n:
            low = mid
        else:
            high = mid - 1
    return low


# 1. Lecture du fichier de test existant
fichier_test = ROOT_DIR / "exemples" / "rapport.txt"
contenu_original = fichier_test.read_bytes()

# 2. Chiffrement du fichier avec une clé aléatoire de 32 octets
file_key = os.urandom(32)
blob = encrypt_bytes(contenu_original, file_key)

# 3. Chiffrement RSA vulnérable (e=3, sans padding)
_, pub_bob = generate_keypair()
wrapped_key = wrap_key(file_key, pub_bob)

# 4. Attaque : calcul de la racine cubique entière du chiffré RSA
c = int.from_bytes(wrapped_key, "big")
recovered_key = integer_cbrt(c).to_bytes(32, "big")

# 5. Déchiffrement du contenu avec la clé récupérée
texte_dechiffre = decrypt_bytes(blob, recovered_key)

print("[+] Clé aléatoire générée :", file_key.hex())
print("[+] Clé aléatoire extraite :", recovered_key.hex())
print("[+] Contenu du fichier récupéré :\n")
print(texte_dechiffre.decode("utf-8"))