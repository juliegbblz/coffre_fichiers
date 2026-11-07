"""Configuration du service CoffreFichiers."""
import os

# Clé utilisée pour signer les tokens de session (HMAC).
TOKEN_SECRET = b"polytech"

# Durée de validité d'un token, en secondes.
TOKEN_TTL = 3600

# Clé maître du service, à partir de laquelle sont dérivées les clés utilisateurs.
MASTER_KEY = os.urandom(32)

# Taille des clés RSA générées pour le partage de fichiers.
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537  # exposant public petit => chiffrement plus rapide
