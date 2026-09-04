import requests
from test_gateway_hit import enroll_device, BASE_URL

if __name__ == "__main__":
    signing_key, did, jwt = enroll_device()
    print("\n✅ Dispositif enrôlé et ACTIF (on-chain + PostgreSQL).")

    resp = requests.patch(
        f"{BASE_URL}/api/v1/admin/devices/{did}/suspend",
        json={"reason": "Test manuel - vérification anti cache-miss"},
    )
    print("\n--- Suspension ---")
    print("HTTP", resp.status_code)
    print(resp.text)

    # Vérification opérationnelle immédiate, avec le JWT frais de cet enrôlement
    resp2 = requests.post(f"{BASE_URL}/api/v1/operational/verify", json={
        "did": did,
        "jwt": jwt,
        "timestamp": 123,
        "proofSignature": "peu-importe-a-ce-stade",
    })
    print("\n--- Vérification opérationnelle (doit être refusée) ---")
    print("HTTP", resp2.status_code)
    print(resp2.text)