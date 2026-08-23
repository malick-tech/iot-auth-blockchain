import json
import os
import signal
import time
from urllib.parse import quote

import paho.mqtt.client as mqtt
import requests


BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "http://host.docker.internal:8083").rstrip("/")
MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
REQUEST_TIMEOUT = int(os.getenv("GATEWAY_BACKEND_TIMEOUT", "20"))
RECONNECT_DELAY = int(os.getenv("GATEWAY_RECONNECT_DELAY", "5"))

TOPICS = (
    ("iot/+/enrollment/first-contact/request", 1),
    ("iot/+/enrollment/challenge-response/request", 1),
    ("iot/+/auth/challenge/request", 1),
    ("iot/+/auth/authenticate/request", 1),
)

# Longueur attendue d'un topic valide : ["iot", <id>, <op...>, "request"]
# Minimum 4 segments, dernier segment = "request".
_MIN_TOPIC_PARTS = 4


def _is_valid_topic(parts: list[str]) -> bool:
    """Vérifie qu'un topic MQTT a la structure attendue avant tout traitement."""
    if len(parts) < _MIN_TOPIC_PARTS:
        return False
    if parts[0] != "iot":
        return False
    if parts[-1] != "request":
        return False
    # L'identifiant de l'appareil (parts[1]) ne doit pas permettre une traversée
    # de chemin une fois utilisé dans une URL. On rejette tout segment vide ou
    # contenant des caractères de contrôle/slashes résiduels.
    device_id = parts[1]
    if not device_id or "/" in device_id or "\\" in device_id or ".." in device_id:
        return False
    return True


def post_backend(path: str, payload: dict) -> tuple[int, dict]:
    response = requests.post(f"{BACKEND_BASE_URL}{path}", json=payload, timeout=REQUEST_TIMEOUT)
    try:
        body = response.json()
    except ValueError:
        body = {"message": response.text}
    return response.status_code, body


def response_topic(parts: list[str], operation: str) -> str:
    return f"iot/{parts[1]}/{operation}/response"


def handle_message(client: mqtt.Client, userdata, msg: mqtt.MQTTMessage) -> None:
    # Bug 2 fix : toutes les exceptions sont capturées pour ne pas tuer
    # le thread de callback MQTT et rendre le bridge silencieusement mort.
    try:
        _process_message(client, msg)
    except Exception as exc:
        print(f"[GW] Erreur inattendue sur topic={msg.topic} : {exc}", flush=True)


def _process_message(client: mqtt.Client, msg: mqtt.MQTTMessage) -> None:
    parts = msg.topic.split("/")

    # Bug 1 fix : validation de la structure du topic avant tout traitement
    if not _is_valid_topic(parts):
        print(f"[GW] Topic malformé ignoré : {msg.topic}", flush=True)
        return

    operation = "/".join(parts[2:-1])
    reply_to = response_topic(parts, operation)

    try:
        payload = json.loads(msg.payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        publish_error(client, reply_to, 400, f"Payload JSON invalide: {exc}")
        return

    try:
        if operation == "enrollment/first-contact":
            status, body = post_backend("/api/enrollment/first-contact", payload)

        elif operation == "enrollment/challenge-response":
            status, body = post_backend("/api/enrollment/challenge-response", payload)

        elif operation == "auth/challenge":
            # Bug 1 fix : le DID est URL-encodé avant insertion dans le chemin HTTP
            # pour éviter toute traversée de chemin ou injection d'endpoint.
            did = payload.get("did") or parts[1]
            status, body = post_backend(f"/api/auth/challenge/{quote(did, safe='')}", {})

        elif operation == "auth/authenticate":
            status, body = post_backend("/api/auth/authenticate", payload)

        else:
            publish_error(client, reply_to, 404, f"Operation gateway inconnue: {operation}")
            return

    except requests.RequestException as exc:
        publish_error(client, reply_to, 502, f"Backend indisponible: {exc}")
        return

    client.publish(reply_to, json.dumps({"status": status, "ok": 200 <= status < 300, "body": body}), qos=1)
    print(f"[GW] {msg.topic} -> {reply_to} status={status}", flush=True)


def publish_error(client: mqtt.Client, topic: str, status: int, message: str) -> None:
    client.publish(topic, json.dumps({"status": status, "ok": False, "body": {"message": message}}), qos=1)
    print(f"[GW] {topic} error={message}", flush=True)


def on_disconnect(client: mqtt.Client, userdata, rc, properties=None) -> None:
    # Bug 3 fix : reconnexion automatique en cas de déconnexion inattendue.
    # rc == 0 = déconnexion propre (arrêt demandé), pas de retry.
    if rc != 0:
        print(f"[GW] Déconnexion inattendue (rc={rc}), tentative de reconnexion...", flush=True)
        while True:
            try:
                client.reconnect()
                # Réabonnement aux topics après reconnexion
                client.subscribe(list(TOPICS))
                print(f"[GW] Reconnecté à {MQTT_HOST}:{MQTT_PORT}", flush=True)
                break
            except Exception as exc:
                print(f"[GW] Reconnexion échouée : {exc}. Nouvel essai dans {RECONNECT_DELAY}s...", flush=True)
                time.sleep(RECONNECT_DELAY)


def main() -> None:
    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = handle_message
    # Bug 3 fix : enregistrement du handler de déconnexion
    client.on_disconnect = on_disconnect
    client.connect(MQTT_HOST, MQTT_PORT)
    client.subscribe(list(TOPICS))
    client.loop_start()
    print(f"[GW] Device gateway bridge connecté à {MQTT_HOST}:{MQTT_PORT}", flush=True)

    try:
        while running:
            time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
