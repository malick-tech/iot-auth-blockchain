import base64
import hashlib
import sys
import time

import nacl.signing
import requests
from algosdk.v2client import algod

BASE_URL = "http://localhost:8083"
ALGOD_ADDRESS = "http://localhost:4001"
ALGOD_TOKEN = "a" * 64
APP_ID = 1014


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
        print(f"\nEchec a l'etape : {step}")
        sys.exit(1)
    return response.json()


def main():
    serial_number = f"IOT-TEST-{int(time.time())}"

    signing_key = nacl.signing.SigningKey.generate()
    public_key_bytes = bytes(signing_key.verify_key)
    public_key_b32 = encode_base32(public_key_bytes)
    did = build_did(public_key_bytes)

    print("Serial      :", serial_number)
    print("DID         :", did)
    print("Public key  :", public_key_b32)

    check(requests.post(f"{BASE_URL}/api/v1/admin/devices", json={
        "serialNumber": serial_number,
        "deviceType": "capteur-temperature",
        "location": "Ziguinchor-Lab",
    }), "Pre-enregistrement")

    sigma0 = sign_b64url(signing_key, serial_number + did)
    challenge = check(requests.post(f"{BASE_URL}/api/v1/enrollment/first-contact", json={
        "serialNumber": serial_number,
        "did": did,
        "publicKey": public_key_b32,
        "signature": sigma0,
    }), "First contact")

    nonce = challenge["nonce"]
    print("Nonce recu  :", nonce)

    sigma1 = sign_b64url(signing_key, nonce)
    check(requests.post(f"{BASE_URL}/api/v1/enrollment/challenge-response", json={
        "did": did,
        "signedNonce": sigma1,
    }), "Challenge response")

    print("\nDispositif active, JWT PoP emis.")

    print("\n--- Verification on-chain did:algo ---")
    algod_client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    data_box_key = hashlib.sha256(public_key_bytes).digest()[:8]

    try:
        box = algod_client.application_box_by_name(APP_ID, public_key_bytes)
        metadata = base64.b64decode(box["value"])
        print("Metadata box trouvee :")
        print("  start_key =", metadata[:8].hex())
        print("  end_key   =", metadata[8:16].hex())
        print("  status    =", metadata[16])
        print("  final_len =", int.from_bytes(metadata[17:25], "big"))
    except Exception as e:
        print("Metadata box introuvable :", e)

    try:
        box = algod_client.application_box_by_name(APP_ID, data_box_key)
        value_bytes = base64.b64decode(box["value"])
        print("Data box trouvee, DID Document :")
        print(" ", value_bytes.decode("utf-8", errors="replace"))
    except Exception as e:
        print("Data box introuvable :", e)


if __name__ == "__main__":
    main()
