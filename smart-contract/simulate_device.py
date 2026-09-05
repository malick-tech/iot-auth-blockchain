import base64

import nacl.signing

APP_ID = 1014


def encode_base32(data: bytes) -> str:
    return base64.b32encode(data).decode("utf-8").rstrip("=")


def build_did(public_key_bytes: bytes) -> str:
    return f"did:algo:custom:app:{APP_ID}:{public_key_bytes.hex()}"


def sign_message(signing_key: nacl.signing.SigningKey, message: str) -> str:
    signature = signing_key.sign(message.encode("utf-8")).signature
    return base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")


if __name__ == "__main__":
    signing_key = nacl.signing.SigningKey.generate()
    verify_key_bytes = bytes(signing_key.verify_key)

    public_key_b32 = encode_base32(verify_key_bytes)
    did = build_did(verify_key_bytes)

    print("=" * 60)
    print("publicKey (Base32) :", public_key_b32)
    print("DID                :", did)
    print("=" * 60)
    print("Cle privee a garder pour signer le nonce ensuite :")
    print(base64.urlsafe_b64encode(bytes(signing_key)).decode("utf-8"))
