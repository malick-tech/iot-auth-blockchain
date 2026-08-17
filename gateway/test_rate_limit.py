import requests

BASE_URL = "http://localhost:8083"

if __name__ == "__main__":
    # /api/auth/challenge/{did} tombe dans la catégorie "auth" du rate limiter.
    # Le DID n'a même pas besoin d'exister : le filtre agit avant que la
    # requête n'atteigne le contrôleur.
    fake_did = "did:algo:RATELIMITTEST00000000000000000000000000000000000000"

    for i in range(1, 26):
        resp = requests.post(f"{BASE_URL}/api/auth/challenge/{fake_did}")
        marker = "🔴 BLOQUÉ" if resp.status_code == 429 else ""
        print(f"Requête {i:2d} -> HTTP {resp.status_code} {marker}")