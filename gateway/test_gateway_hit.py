import base64
import json
import time

import nacl.signing
import requests
import paho.mqtt.client as mqtt

BASE_URL = "http://localhost:8083"       # <-- adapte au port actuel du backend
MQTT_HOST = "localhost"
MQTT_PORT = 1883
APP_ID = 1010


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
        raise SystemExit(f"Echec a l'etape : {step}")
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
    }), "Challenge response (remplit le cache Redis)")

    return signing_key, did, jwt_response["jwt"]


def test_via_gateway(signing_key, did, jwt):
    claims = decode_jwt_payload(jwt)
    jti = claims["jti"]

    timestamp = int(time.time())
    proof_message = f"{jti}:{timestamp}"
    proof_signature = sign_b64url(signing_key, proof_message)

    request_topic = f"iot/{did}/operational/request"
    response_topic = f"iot/{did}/operational/response"

    received = {}

    def on_message(client, userdata, msg):
        received["payload"] = json.loads(msg.payload.decode("utf-8"))
        client.disconnect()

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    client.connect(MQTT_HOST, MQTT_PORT)
    client.subscribe(response_topic)

    payload = {
        "jwt": jwt,
        "timestamp": timestamp,
        "proofSignature": proof_signature,
        "requestedPermission": "device:read",
    }

    print(f"\n--- Publication MQTT sur {request_topic} ---")
    client.publish(request_topic, json.dumps(payload))

    print(f"En attente de la réponse sur {response_topic} ...")
    client.loop_start()
    timeout = time.time() + 10
    while "payload" not in received and time.time() < timeout:
        time.sleep(0.1)
    client.loop_stop()

    if "payload" not in received:
        raise SystemExit("❌ Timeout : aucune réponse reçue sur MQTT")

    print("\n--- Réponse reçue via la Gateway ---")
    print(json.dumps(received["payload"], indent=2))


if __name__ == "__main__":
    signing_key, did, jwt = enroll_device()
    print("\n✅ Dispositif enrôlé, cache Redis rempli.")
    test_via_gateway(signing_key, did, jwt)
