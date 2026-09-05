"""
Test du renouvellement JWT PoP via Verifiable Presentation, après ajout de :
- la vérification de signature de l'Issuer sur le VC
- la résolution on-chain du statut ACTIVE

Nécessite : requests, pynacl (déjà installés dans smart-contract/gateway venv)
Nécessite aussi psql accessible via docker exec pour récupérer le vcId
(aucune API publique ne l'expose actuellement).

Usage : place ce script dans gateway/ (à côté de test_gateway_hit.py) et lance-le,
ou adapte BASE_URL/POSTGRES_CONTAINER si besoin.
"""
import base64
import json
import subprocess
import time

import nacl.signing
import requests

BASE_URL = "http://localhost:8083"
APP_ID = 1014
POSTGRES_CONTAINER = "iot-auth-postgres-1"
POSTGRES_USER = "malick"
POSTGRES_DB = "iot_auth_db"


def encode_base32(data: bytes) -> str:
    return base64.b32encode(data).decode("utf-8").rstrip("=")


def build_did(public_key_bytes: bytes) -> str:
    return f"did:algo:custom:app:{APP_ID}:{public_key_bytes.hex()}"


def sign_b64url(signing_key: nacl.signing.SigningKey, message: str) -> str:
    signature = signing_key.sign(message.encode("utf-8")).signature
    return base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")


def check(response: requests.Response, step: str):
    print(f"\n--- {step} ---")
    print("HTTP", response.status_code)
    print(response.text)
    if not response.ok:
        raise SystemExit(f"Echec a l'etape : {step}")
    return response.json()


def enroll_device():
    serial_number = f"IOT-RENEW-{int(time.time())}"
    signing_key = nacl.signing.SigningKey.generate()
    public_key_bytes = bytes(signing_key.verify_key)
    public_key_b32 = encode_base32(public_key_bytes)
    did = build_did(public_key_bytes)

    print("Serial :", serial_number)
    print("DID    :", did)

    check(requests.post(f"{BASE_URL}/api/v1/admin/devices", json={
        "serialNumber": serial_number,
        "deviceType": "capteur-temperature",
        "location": "Ziguinchor-Lab",
    }), "Pré-enregistrement")

    sigma0 = sign_b64url(signing_key, serial_number + did)
    challenge = check(requests.post(f"{BASE_URL}/api/v1/enrollment/first-contact", json={
        "serialNumber": serial_number,
        "did": did,
        "publicKey": public_key_b32,
        "signature": sigma0,
    }), "First contact")

    sigma1 = sign_b64url(signing_key, challenge["nonce"])
    check(requests.post(f"{BASE_URL}/api/v1/enrollment/challenge-response", json={
        "did": did,
        "signedNonce": sigma1,
    }), "Challenge response")

    return signing_key, did


def get_vc_id(did: str) -> str:
    result = subprocess.run(
        [
            "docker", "exec", POSTGRES_CONTAINER,
            "psql", "-U", POSTGRES_USER, "-d", POSTGRES_DB,
            "-t", "-A",
            "-c", f"SELECT vc_id FROM verifiable_credentials WHERE subject_did = '{did}' ORDER BY issued_at DESC LIMIT 1;"
        ],
        capture_output=True, text=True,
    )
    vc_id = result.stdout.strip()
    if not vc_id:
        raise SystemExit(f"Impossible de récupérer le vcId : {result.stderr}")
    return vc_id


def test_renewal(signing_key, did):
    vc_id = get_vc_id(did)
    print("\nvcId récupéré :", vc_id)

    challenge = check(
        requests.post(f"{BASE_URL}/api/v1/auth/challenge/{did}"),
        "Demande de challenge de renouvellement"
    )
    nonce = challenge["nonce"]

    vp = json.dumps({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "verifiableCredential": [{"id": vc_id}],
    })

    signature = sign_b64url(signing_key, nonce + vp)

    check(requests.post(f"{BASE_URL}/api/v1/auth/authenticate", json={
        "did": did,
        "verifiablePresentation": vp,
        "challenge": nonce,
        "signature": signature,
    }), "Renouvellement JWT (authenticate)")


if __name__ == "__main__":
    signing_key, did = enroll_device()
    print("\n✅ Dispositif enrôlé.")
    test_renewal(signing_key, did)
