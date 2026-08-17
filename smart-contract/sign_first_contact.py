import base64
import os

import nacl.signing

APP_ID = int(os.getenv("ALGORAND_APP_ID", "1010"))
PRIVATE_KEY_B64 = os.getenv("DEVICE_PRIVATE_KEY_B64", "")
SERIAL_NUMBER = os.getenv("DEVICE_SERIAL_NUMBER", "IOT-TEST-001")


def build_did(public_key_bytes: bytes) -> str:
    return f"did:algo:custom:app:{APP_ID}:{public_key_bytes.hex()}"


if __name__ == "__main__":
    if not PRIVATE_KEY_B64:
        raise RuntimeError("Set DEVICE_PRIVATE_KEY_B64 before signing first contact.")

    private_key_bytes = base64.urlsafe_b64decode(PRIVATE_KEY_B64 + "==")
    signing_key = nacl.signing.SigningKey(private_key_bytes)
    did = build_did(bytes(signing_key.verify_key))

    message = SERIAL_NUMBER + did
    signature = signing_key.sign(message.encode("utf-8")).signature
    signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    print("DID :", did)
    print("Message signe (serialNumber + did) :", message)
    print("Signature (sigma0) :", signature_b64)
