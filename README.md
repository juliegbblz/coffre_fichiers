# CoffreFichiers

Service interne de stockage de fichiers chiffrés.

```
coffre_fichiers/
├── app/                  # service actuellement en production (à auditer)
│   ├── app.py            #   endpoints Flask
│   ├── auth.py           #   mots de passe et tokens
│   ├── config.py         #   paramètres et secrets
│   ├── crypto_utils.py   #   chiffrement des fichiers
│   └── sharing.py        #   partage de fichiers (RSA)
└── exemples/             # fichiers de test
```

## 1. Installation

Python 3.10 ou plus récent.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Lancer le service

```bash
python -m app.app                  # http://127.0.0.1:5000
```

Les commandes suivantes sont à lancer dans un autre terminal.

**Créer deux comptes**

```bash
curl -X POST http://127.0.0.1:5000/register -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"motdepasse-alice"}'
curl -X POST http://127.0.0.1:5000/register -H "Content-Type: application/json" \
     -d '{"username":"bob","password":"motdepasse-bob"}'
```

**Se connecter**

```bash
curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"motdepasse-alice"}'
# {"token":"YWxpY2V8MTc2..."}
TOKEN_A="<token d'alice>"
```

**Déposer, lister, télécharger**

```bash
curl -X POST http://127.0.0.1:5000/upload -H "Authorization: Bearer $TOKEN_A" \
     -F "file=@exemples/rapport.txt"
# {"file_id":"file-1","len":...}

curl http://127.0.0.1:5000/files -H "Authorization: Bearer $TOKEN_A"
curl http://127.0.0.1:5000/download/file-1 -H "Authorization: Bearer $TOKEN_A" -o sortie.txt
```

**Partager un fichier et consulter une clé publique**

```bash
curl -X POST http://127.0.0.1:5000/share/file-1 -H "Authorization: Bearer $TOKEN_A" \
     -H "Content-Type: application/json" -d '{"to":"bob"}'
curl http://127.0.0.1:5000/pubkey/bob
```

Bob peut ensuite télécharger `file-1` avec son propre token.

| Endpoint | Méthode | Authentifié | Description |
|---|---|---|---|
| `/register` | POST | non | Crée un compte (`username`, `password`) |
| `/login` | POST | non | Renvoie un token de session |
| `/pubkey/<username>` | GET | non | Clé publique RSA d'un utilisateur |
| `/upload` | POST | oui | Dépose un fichier (chiffré avant stockage) |
| `/files` | GET | oui | Liste ses fichiers et ceux partagés avec soi |
| `/download/<file_id>` | GET | oui | Télécharge un fichier en clair |
| `/share/<file_id>` | POST | oui | Partage un de ses fichiers (`{"to": "<username>"}`) |

Le stockage est en mémoire : tout est perdu à l'arrêt du service.
