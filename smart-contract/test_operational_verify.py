import base64
import json
import time

import nacl.signing
import requests

BASE_URL = "http://localhost:8083"  # <-- adapte au port actuel
APP_ID = 1014


def encode_base32(data: bytes) -> str:
    return base64.b32encode(data).decode("utf-8").rstrip("=")


def build_did(public_key_bytes: bytes) -> str:
    return f"did:algo:custom:app:{APP_ID}:{public_key_bytes.hex()}"


def sign_b64url(signing_key: nacl.signing.SigningKey, message: str) -> str:
    signature = signing_key.sign(message.encode("utf-8")).signature
    return base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")


def decode_jwt_payload(jwt: str) -> dict:
    payload_b64 = jwt.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(payload_json)


def check(response: requests.Response, step: str):
    print(f"\n--- {step} ---")
    print("HTTP", response.status_code)
    print(response.text)
    if not response.ok:
        print(f"\n❌ Echec a l'etape : {step}")
        raise SystemExit(1)
    return response.json()


def enroll_device():
    serial_number = f"IOT-TEST-{int(time.time())}"
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
    jwt_response = check(requests.post(f"{BASE_URL}/api/v1/enrollment/challenge-response", json={
        "did": did,
        "signedNonce": sigma1,
    }), "Challenge response")

    return signing_key, did, jwt_response["jwt"]


def test_operational_verify(signing_key, did, jwt):
    claims = decode_jwt_payload(jwt)
    jti = claims["jti"]
    print("\njti extrait du JWT :", jti)

    timestamp = int(time.time())
    proof_message = f"{jti}:{timestamp}"
    proof_signature = sign_b64url(signing_key, proof_message)

    check(requests.post(f"{BASE_URL}/api/v1/operational/verify", json={
        "did": did,
        "jwt": jwt,
        "timestamp": timestamp,
        "proofSignature": proof_signature,
    }), "Vérification opérationnelle (cache MISS forcé)")


if __name__ == "__main__":
    signing_key, did, jwt = enroll_device()
    print("\n✅ Dispositif enrôlé, JWT PoP obtenu.")
    test_operational_verify(signing_key, did, jwt)
