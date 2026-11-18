import time
import hashlib

def hash_password(password: str) -> str:
    """Copie de app/auth.py ligne 12-14."""
    return hashlib.sha256(password.encode()).hexdigest()


# 1. Simulation de la fuite de la base USERS (via les sauvegardes)
base_fuitee = {
    "alice": hash_password("soleil123"),
    "bob":   hash_password("soleil123"),  # Même mot de passe qu'Alice
    "carol": hash_password("motdepasse"),
}

# 2. Preuve de l'absence de sel (salt)
print("  1. Vérification du sel  ")
print("Empreinte d'Alice :", base_fuitee["alice"])
print("Empreinte de Bob   :", base_fuitee["bob"])

if base_fuitee["alice"] == base_fuitee["bob"]:
    print("-> Constat : Les empreintes sont identiques. Aucun sel utilisé.\n")

# 3. Recherche par dictionnaire (hors-ligne)
print("  2. Test d'un dictionnaire de mots de passe  ")

# On aurait pu utiliser un vrai dictionnaire de mots de passe, mais pour la démonstration on se limite à quelques mots simples.
dictionnaire = ["123456", "password", "soleil123", "qwerty", "admin"]
empreinte_cible = base_fuitee["alice"]

for mot in dictionnaire:
    if hash_password(mot) == empreinte_cible:
        print(f"-> Mot de passe d'Alice retrouvé : '{mot}'\n")
        break

# 4. Mesure de la vitesse de calcul (absence de ralentissement)
print("  3. Vitesse de calcul de SHA-256  ")
nombre_essais = 500_000
debut = time.time()

for i in range(nombre_essais):
    hash_password(str(i))

duree = time.time() - debut
vitesse = int(nombre_essais / duree)
print(f"-> {nombre_essais} empreintes calculées en {duree:.2f} secondes ({vitesse} hash/s).")