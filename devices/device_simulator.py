import argparse
import base64
import json
import signal
import sys
import time
from pathlib import Path

import nacl.signing
import paho.mqtt.client as mqtt


DEFAULT_MQTT_HOST = "localhost"
DEFAULT_MQTT_PORT = 1883
DEFAULT_APP_ID = 1014
STATE_DIR = Path(__file__).resolve().parent / "state"


def encode_base32(data: bytes) -> str:
    return base64.b32encode(data).decode("utf-8").rstrip("=")


def encode_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def decode_b64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def decode_jwt_payload(jwt: str) -> dict:
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("JWT invalide")
    return json.loads(decode_b64url(parts[1]))


def build_did(public_key_bytes: bytes, app_id: int) -> str:
    return f"did:algo:custom:app:{app_id}:{public_key_bytes.hex()}"


def sign_b64url(signing_key: nacl.signing.SigningKey, message: str) -> str:
    signature = signing_key.sign(message.encode("utf-8")).signature
    return encode_b64url(signature)


def state_path(serial: str) -> Path:
    safe_serial = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in serial)
    return STATE_DIR / f"{safe_serial}.json"


def load_or_create_identity(serial: str, app_id: int) -> dict:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = state_path(serial)
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            identity = json.load(fh)
        if identity.get("serialNumber") != serial:
            raise RuntimeError(f"Identite locale incoherente : {path} ne correspond pas au serial {serial}")
        return identity

    signing_key = nacl.signing.SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)
    identity = {
        "serialNumber": serial,
        "privateKeyBase64": base64.b64encode(private_key).decode("utf-8"),
        "publicKeyBase32": encode_base32(public_key),
        "did": build_did(public_key, app_id),
        "jwt": None,
        "credentialId": None,
        "verifiableCredential": None,
        "expiresAt": None,
    }
    save_state(identity)
    return identity


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with state_path(state["serialNumber"]).open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def signing_key_from_state(state: dict) -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey(base64.b64decode(state["privateKeyBase64"]))


class GatewayRpcClient:
    def __init__(self, host: str, port: int, timeout: int):
        self.timeout = timeout
        self.responses = {}
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_message = self._on_message
        self.client.connect(host, port)
        self.client.loop_start()

    def close(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()

    def request(self, request_topic: str, response_topic: str, payload: dict, step: str) -> dict:
        self.responses.pop(response_topic, None)
        self.client.subscribe(response_topic, qos=1)
        self.client.publish(request_topic, json.dumps(payload), qos=1)

        deadline = time.time() + self.timeout
        while response_topic not in self.responses and time.time() < deadline:
            time.sleep(0.1)

        self.client.unsubscribe(response_topic)
        response = self.responses.pop(response_topic, None)
        if response is None:
            raise RuntimeError(f"{step} sans reponse gateway apres {self.timeout}s")
        if not response.get("ok"):
            status = response.get("status")
            body = response.get("body")
            raise RuntimeError(f"{step} refuse via gateway ({status}) : {body}")
        return response.get("body") or {}

    def _on_message(self, _client, _userdata, msg):
        try:
            self.responses[msg.topic] = json.loads(msg.payload.decode("utf-8"))
        except json.JSONDecodeError:
            self.responses[msg.topic] = {
                "ok": False,
                "status": 502,
                "body": {"message": msg.payload.decode("utf-8", errors="replace")},
            }


def is_jwt_valid(state: dict, renew_margin_seconds: int) -> bool:
    jwt = state.get("jwt")
    if not jwt:
        return False
    try:
        exp = int(decode_jwt_payload(jwt)["exp"])
    except Exception:
        return False
    return exp - int(time.time()) > renew_margin_seconds


def enroll_device(state: dict, gateway: GatewayRpcClient) -> None:
    signing_key = signing_key_from_state(state)
    serial = state["serialNumber"]
    did = state["did"]

    first_signature = sign_b64url(signing_key, serial + did)
    challenge = gateway.request(
        f"iot/{serial}/enrollment/first-contact/request",
        f"iot/{serial}/enrollment/first-contact/response",
        {
            "serialNumber": serial,
            "did": did,
            "publicKey": state["publicKeyBase32"],
            "signature": first_signature,
        },
        "first-contact",
    )

    nonce_signature = sign_b64url(signing_key, challenge["nonce"])
    jwt_response = gateway.request(
        f"iot/{did}/enrollment/challenge-response/request",
        f"iot/{did}/enrollment/challenge-response/response",
        {
            "did": did,
            "signedNonce": nonce_signature,
        },
        "challenge-response",
    )

    update_auth_state(state, jwt_response)
    save_state(state)


def update_auth_state(state: dict, jwt_response: dict) -> None:
    jwt = jwt_response.get("jwtToken") or jwt_response.get("jwt")
    if not jwt:
        raise RuntimeError("La reponse backend ne contient pas de JWT")
    state["jwt"] = jwt
    state["credentialId"] = jwt_response.get("credentialId") or state.get("credentialId")
    state["verifiableCredential"] = jwt_response.get("verifiableCredential") or state.get("verifiableCredential")
    state["expiresAt"] = jwt_response.get("expiresAt")


def build_verifiable_presentation(state: dict) -> str:
    credential = state.get("verifiableCredential")
    if credential:
        try:
            credential = json.loads(credential)
        except json.JSONDecodeError:
            pass
    else:
        credential = {"id": state["credentialId"]}

    return json.dumps(
        {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": "VerifiablePresentation",
            "verifiableCredential": [credential],
        },
        separators=(",", ":"),
    )


def renew_jwt(state: dict, gateway: GatewayRpcClient) -> None:
    signing_key = signing_key_from_state(state)
    challenge = gateway.request(
        f"iot/{state['did']}/auth/challenge/request",
        f"iot/{state['did']}/auth/challenge/response",
        {"did": state["did"]},
        "auth-challenge",
    )
    vp = build_verifiable_presentation(state)
    signature = sign_b64url(signing_key, challenge["nonce"] + vp)
    jwt_response = gateway.request(
        f"iot/{state['did']}/auth/authenticate/request",
        f"iot/{state['did']}/auth/authenticate/response",
        {
            "did": state["did"],
            "verifiablePresentation": vp,
            "challenge": challenge["nonce"],
            "signature": signature,
        },
        "authenticate",
    )
    update_auth_state(state, jwt_response)
    save_state(state)


def publish_operational_request(client, state: dict, permission: str) -> None:
    signing_key = signing_key_from_state(state)
    claims = decode_jwt_payload(state["jwt"])
    timestamp = int(time.time())
    proof_signature = sign_b64url(signing_key, f"{claims['jti']}:{timestamp}")
    topic = f"iot/{state['did']}/operational/request"
    payload = {
        "jwt": state["jwt"],
        "timestamp": timestamp,
        "proofSignature": proof_signature,
        "requestedPermission": permission,
    }
    client.publish(topic, json.dumps(payload), qos=1)
    print(f"[TX] {topic} permission={permission} ts={timestamp}")


def run_device(args) -> None:
    state = load_or_create_identity(args.serial, args.app_id)

    print("Device pret")
    print(f"  serial    : {state['serialNumber']}")
    print(f"  did       : {state['did']}")
    print(f"  publicKey : {state['publicKeyBase32']}")
    print("Assure-toi que ce serial est pre-enregistre par l'admin avant le premier contact.")

    gateway = GatewayRpcClient(args.mqtt_host, args.mqtt_port, args.gateway_timeout)
    while not is_jwt_valid(state, args.renew_margin):
        try:
            print("[AUTH] Enrolement du dispositif via gateway MQTT...")
            enroll_device(state, gateway)
            print("[AUTH] Enrolement termine, JWT PoP obtenu.")
        except Exception as exc:
            print(f"[AUTH] En attente du pre-enregistrement admin ou des services : {exc}")
            time.sleep(args.retry_delay)

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    response_topic = f"iot/{state['did']}/operational/response"

    def on_message(_client, _userdata, msg):
        payload = msg.payload.decode("utf-8", errors="replace")
        print(f"[RX] {msg.topic} {payload}")

    client.on_message = on_message
    client.connect(args.mqtt_host, args.mqtt_port)
    client.subscribe(response_topic)
    client.loop_start()
    print(f"[MQTT] Connecte a {args.mqtt_host}:{args.mqtt_port}, ecoute {response_topic}")

    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    try:
        while running:
            try:
                if not is_jwt_valid(state, args.renew_margin):
                    print("[AUTH] JWT proche expiration, renouvellement via gateway...")
                    renew_jwt(state, gateway)
                    print("[AUTH] JWT renouvele.")
                publish_operational_request(client, state, args.permission)
            except Exception as exc:
                print(f"[WARN] Cycle operationnel echoue : {exc}")
            time.sleep(args.interval)
    finally:
        client.loop_stop()
        client.disconnect()
        gateway.close()
        save_state(state)
        print("Device arrete proprement.")


def parse_args():
    parser = argparse.ArgumentParser(description="Simulateur de dispositif IoT DID/VC/JWT PoP")
    parser.add_argument("--serial", required=True, help="Numero de serie pre-enregistre par l'admin")
    parser.add_argument("--type", default="capteur-temperature", help="Type informatif du dispositif")
    parser.add_argument("--location", default="Ziguinchor-Lab", help="Emplacement informatif du dispositif")
    parser.add_argument("--mqtt-host", default=DEFAULT_MQTT_HOST)
    parser.add_argument("--mqtt-port", type=int, default=DEFAULT_MQTT_PORT)
    parser.add_argument("--gateway-timeout", type=int, default=20, help="Timeout des reponses gateway MQTT")
    parser.add_argument("--app-id", type=int, default=DEFAULT_APP_ID)
    parser.add_argument("--interval", type=int, default=15, help="Delai entre deux requetes operationnelles")
    parser.add_argument("--retry-delay", type=int, default=5, help="Delai de retry si le pre-enregistrement manque")
    parser.add_argument("--renew-margin", type=int, default=60, help="Renouvelle le JWT s'il expire dans moins de N secondes")
    parser.add_argument("--permission", default="device:read", help="Permission demandee a la gateway")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        run_device(parse_args())
    except KeyboardInterrupt:
        sys.exit(0)
