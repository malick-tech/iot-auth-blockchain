import argparse
import base64
import json
import os
import random
import signal
import sys
import time
from pathlib import Path

import nacl.signing
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


DEFAULT_MQTT_HOST = "localhost"
DEFAULT_MQTT_PORT = 1883
DEFAULT_APP_ID = 1014
DEFAULT_MAX_ENROLL_ATTEMPTS = 20
STATE_DIR = Path(__file__).resolve().parent / "state"
MASTER_KEY_PATH = STATE_DIR / ".master.key"
DEVICE_STARTED_AT = time.time()

# ---------------------------------------------------------------------------
# Chiffrement au repos de la cle privee (equivalent simule du NVS chiffre
# d'un ESP32 reel - section 3.2.1 du memoire).
#
# Note d'implementation : le memoire mentionne AES-XTS (mode utilise par
# l'API NVS Encryption d'Espressif pour chiffrer des secteurs de flash).
# XTS est concu pour des blocs de taille fixe sans authentification
# integree - adapte a du stockage flash brut, mais pas a un seul petit
# blob (32 octets de cle privee) dans un fichier JSON. On utilise ici
# AES-256-GCM : meme niveau de securite pour ce cas d'usage, avec en plus
# une authentification integree (toute alteration du fichier est detectee
# au dechiffrement). Sur un vrai firmware ESP32, c'est bien l'API NVS
# Encryption (AES-XTS) qu'il faut utiliser.
#
# Sur un ESP32 reel, la cle de chiffrement NVS est derivee d'un secret
# grave dans l'eFuse a la fabrication (protection materielle, jamais
# lisible depuis le logiciel). Ici, cette clef materielle est simulee par
# un fichier local "state/.master.key" genere une seule fois. C'est le
# secret qui, sur un vrai dispositif, serait protege par le hardware -
# on ne peut pas simuler une vraie racine de confiance materielle depuis
# un simple script Python.
# ---------------------------------------------------------------------------


def load_or_create_master_key() -> bytes:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if MASTER_KEY_PATH.exists():
        return base64.b64decode(MASTER_KEY_PATH.read_text().strip())

    master_key = os.urandom(32)
    MASTER_KEY_PATH.write_text(base64.b64encode(master_key).decode("utf-8"))
    try:
        os.chmod(MASTER_KEY_PATH, 0o600)
    except OSError:
        pass  # best-effort sur systemes qui ne supportent pas chmod (ex: Windows)
    print(f"[SECURITY] Nouvelle cle maitresse generee : {MASTER_KEY_PATH}")
    print("[SECURITY] Sur un vrai dispositif, cette cle serait provisionnee en usine dans l'eFuse.")
    return master_key


def derive_device_key(master_key: bytes, serial: str) -> bytes:
    """Derive une cle AES-256 propre a ce dispositif a partir de la cle maitresse."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=serial.encode("utf-8"),
        info=b"iot-auth-blockchain:private-key-encryption",
    ).derive(master_key)


def encrypt_private_key(master_key: bytes, serial: str, private_key: bytes) -> dict:
    device_key = derive_device_key(master_key, serial)
    aesgcm = AESGCM(device_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key, associated_data=serial.encode("utf-8"))
    return {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_private_key(master_key: bytes, serial: str, encrypted: dict) -> bytes:
    device_key = derive_device_key(master_key, serial)
    aesgcm = AESGCM(device_key)
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=serial.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError(
            f"Impossible de dechiffrer la cle privee de {serial} : fichier corrompu, "
            "altere, ou cle maitresse differente de celle utilisee au chiffrement."
        ) from exc


# ---------------------------------------------------------------------------


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


def load_or_create_identity(serial: str, app_id: int, master_key: bytes) -> dict:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = state_path(serial)
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            identity = json.load(fh)
        if identity.get("serialNumber") != serial:
            raise RuntimeError(f"Identite locale incoherente : {path} ne correspond pas au serial {serial}")

        # Migration depuis l'ancien format (cle privee stockee en clair sous
        # "privateKeyBase64"). On chiffre la cle existante et on reecrit le
        # fichier, sans rien perdre : meme DID, meme JWT, meme historique.
        if "privateKeyEncrypted" not in identity and "privateKeyBase64" in identity:
            print(f"[SECURITY] Migration de {path.name} vers le stockage chiffre (ancien format detecte)...")
            private_key = base64.b64decode(identity.pop("privateKeyBase64"))
            identity["privateKeyEncrypted"] = encrypt_private_key(master_key, serial, private_key)
            save_state(identity)
            print(f"[SECURITY] Migration terminee : {path.name} ne contient plus de cle en clair.")

        # Format inconnu : ni le format chiffre actuel, ni l'ancien format en
        # clair. Plutot que de planter avec un KeyError cryptique, on donne
        # un diagnostic exploitable (quelles cles sont presentes) et une
        # piste de resolution.
        if "privateKeyEncrypted" not in identity:
            known_key_fields = {"privateKeyEncrypted", "privateKeyBase64"}
            present_fields = sorted(identity.keys())
            raise RuntimeError(
                f"Format de {path} non reconnu : aucune cle privee exploitable trouvee.\n"
                f"  Champs presents dans le fichier : {present_fields}\n"
                f"  Champs de cle privee attendus (l'un des deux) : {sorted(known_key_fields)}\n"
                f"Ce fichier vient probablement d'une version encore plus ancienne du simulateur.\n"
                f"Options : (1) envoyer le contenu de ce fichier pour ajouter la migration correspondante, "
                f"ou (2) si ce dispositif est un test jetable, supprimer {path} et relancer "
                f"(genere une nouvelle identite -> necessite un nouveau pre-enregistrement admin avec le nouveau DID)."
            )

        # Verifie que la cle privee est bien dechiffrable des le chargement,
        # plutot que d'echouer plus tard au premier besoin de signature.
        decrypt_private_key(master_key, serial, identity["privateKeyEncrypted"])
        return identity

    signing_key = nacl.signing.SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)
    identity = {
        "serialNumber": serial,
        "privateKeyEncrypted": encrypt_private_key(master_key, serial, private_key),
        "publicKeyBase32": encode_base32(public_key),
        "did": build_did(public_key, app_id),
        "jwt": None,
        "credentialId": None,
        "verifiableCredential": None,
        "expiresAt": None,
    }
    save_state(identity)
    print(f"[SECURITY] Cle privee de {serial} chiffree au repos dans {state_path(serial)}")
    return identity


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = state_path(state["serialNumber"])
    with path.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def signing_key_from_state(state: dict, master_key: bytes) -> nacl.signing.SigningKey:
    private_key = decrypt_private_key(master_key, state["serialNumber"], state["privateKeyEncrypted"])
    return nacl.signing.SigningKey(private_key)


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


def enroll_device(state: dict, gateway: GatewayRpcClient, master_key: bytes) -> None:
    signing_key = signing_key_from_state(state, master_key)
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


def renew_jwt(state: dict, gateway: GatewayRpcClient, master_key: bytes) -> None:
    signing_key = signing_key_from_state(state, master_key)
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


def publish_operational_request(client, state: dict, permission: str, master_key: bytes) -> None:
    signing_key = signing_key_from_state(state, master_key)
    claims = decode_jwt_payload(state["jwt"])
    timestamp = int(time.time())
    proof_signature = sign_b64url(signing_key, f"{claims['jti']}:{timestamp}")
    topic = f"iot/{state['did']}/operational/request"
    payload = {
        "jwt": state["jwt"],
        "timestamp": timestamp,
        "proofSignature": proof_signature,
        "requestedPermission": permission,
        "metrics": {
            "temperatureC": round(22.0 + random.uniform(-2.5, 2.5), 2),
            "humidityPercent": round(50.0 + random.uniform(-8.0, 8.0), 2),
            "batteryPercent": 100,
            "uptimeSeconds": int(time.time() - DEVICE_STARTED_AT),
            "measuredAt": int(time.time()),
        },
    }
    client.publish(topic, json.dumps(payload), qos=1)
    print(f"[TX] {topic} permission={permission} ts={timestamp}")


class EnrollmentAbandoned(RuntimeError):
    """Leve quand le nombre maximal de tentatives d'enrolement est atteint."""


def wait_for_enrollment(
    state: dict, gateway: GatewayRpcClient, master_key: bytes, retry_delay: int, max_attempts: int
) -> None:
    attempt = 0
    while not is_jwt_valid(state, 0):
        attempt += 1
        try:
            action = "Renouvellement de l'authentification" if state.get("verifiableCredential") else "Enrolement du dispositif"
            print(f"[AUTH] {action} via gateway MQTT... (tentative {attempt}"
                  + (f"/{max_attempts}" if max_attempts > 0 else "") + ")")
            if state.get("verifiableCredential"):
                renew_jwt(state, gateway, master_key)
                print("[AUTH] Authentification renouvelee, JWT PoP obtenu.")
            else:
                enroll_device(state, gateway, master_key)
                print("[AUTH] Enrolement termine, JWT PoP obtenu.")
            return
        except Exception as exc:
            print(f"[AUTH] En attente du pre-enregistrement admin ou des services : {exc}")
            if max_attempts > 0 and attempt >= max_attempts:
                raise EnrollmentAbandoned(
                    f"Echec de l'enrolement apres {attempt} tentatives ({max_attempts} max). "
                    "Verifie que : (1) le serial est bien pre-enregistre cote admin, "
                    "(2) le gateway MQTT et le backend sont demarres, "
                    "(3) --app-id correspond au smart contract deploye."
                ) from exc
            time.sleep(retry_delay)


def run_device(args) -> None:
    master_key = load_or_create_master_key()
    state = load_or_create_identity(args.serial, args.app_id, master_key)

    print("Device pret")
    print(f"  serial    : {state['serialNumber']}")
    print(f"  did       : {state['did']}")
    print(f"  publicKey : {state['publicKeyBase32']}")
    print("Assure-toi que ce serial est pre-enregistre par l'admin avant le premier contact.")

    gateway = GatewayRpcClient(args.mqtt_host, args.mqtt_port, args.gateway_timeout)

    try:
        wait_for_enrollment(state, gateway, master_key, args.retry_delay, args.max_enroll_attempts)
    except EnrollmentAbandoned as exc:
        print(f"[FATAL] {exc}")
        gateway.close()
        sys.exit(1)

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
                    renew_jwt(state, gateway, master_key)
                    print("[AUTH] JWT renouvele.")
                publish_operational_request(client, state, args.permission, master_key)
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
    parser.add_argument(
        "--max-enroll-attempts",
        type=int,
        default=DEFAULT_MAX_ENROLL_ATTEMPTS,
        help="Nombre max de tentatives d'enrolement avant abandon (0 = illimite)",
    )
    parser.add_argument("--renew-margin", type=int, default=60, help="Renouvelle le JWT s'il expire dans moins de N secondes")
    parser.add_argument("--permission", default="device:read", help="Permission demandee a la gateway")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        run_device(parse_args())
    except KeyboardInterrupt:
        sys.exit(0)