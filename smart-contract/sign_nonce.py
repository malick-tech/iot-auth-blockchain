import base64
import os

import nacl.signing

PRIVATE_KEY_B64 = os.getenv("DEVICE_PRIVATE_KEY_B64", "")
NONCE = os.getenv("DEVICE_NONCE", "")

if __name__ == "__main__":
    if not PRIVATE_KEY_B64:
        raise RuntimeError("Set DEVICE_PRIVATE_KEY_B64 before signing the nonce.")
    if not NONCE:
        raise RuntimeError("Set DEVICE_NONCE before signing the nonce.")

    private_key_bytes = base64.urlsafe_b64decode(PRIVATE_KEY_B64 + "==")
    signing_key = nacl.signing.SigningKey(private_key_bytes)

    signature = signing_key.sign(NONCE.encode("utf-8")).signature
    signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    print("signedNonce (sigma1) :", signature_b64)
