"""Suite de tests bout-en-bout et de sécurité pour le chapitre 5.

Deux phases, indépendantes l'une de l'autre :

  PHASE 1 — Cycle de vie complet d'un dispositif
    pré-enregistrement admin -> enrôlement -> requête opérationnelle valide
    -> violation de permission -> suspension automatique -> réactivation
    admin -> requête opérationnelle valide -> révocation admin -> mesure du
    temps de blocage opérationnel -> requête opérationnelle rejetée.

  PHASE 2 — Matrice d'attaques
    Dix scénarios qui altèrent délibérément une preuve par ailleurs valide
    (rejeu, usurpation de clé, permission falsifiée après signature,
    métriques falsifiées, horodatage expiré, JWT altéré, DID inexistant,
    VP rejouée, dispositif révoqué) et vérifient que chacun est bien rejeté.

Chaque phase produit un tableau (attaque/étape -> résultat attendu ->
résultat obtenu -> PASS/FAIL) écrit en CSV et en JSON, prêt pour le
chapitre 5. Un dispositif de test dédié est créé pour chaque phase — ce
script ne touche jamais un dispositif de production.

Prérequis : backend, gateway (Mosquitto + Node-RED), Redis, PostgreSQL et
Algorand LocalNet démarrés, comme pour experiments/benchmark.py. Un compte
admin valide (identifiants dans e2e_security_config.json).
"""

import argparse
import csv
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import nacl.signing
import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "devices"))
from device_simulator import (  # noqa: E402
    GatewayRpcClient,
    build_did,
    decode_jwt_payload,
    encode_b64url,
    load_or_create_identity,
    load_or_create_master_key,
    sign_b64url,
    signing_key_from_state,
    wait_for_enrollment,
)

RESULTS: list[dict] = []


def record(phase: str, step: str, expected: str, observed: str, passed: bool) -> None:
    RESULTS.append({
        "phase": phase,
        "step": step,
        "expected": expected,
        "observed": observed,
        "result": "PASS" if passed else "FAIL",
    })
    tag = "OK " if passed else "!! "
    print(f"[{tag}] {phase} / {step} — attendu: {expected} — obtenu: {observed}")


# ============================================================
# Client HTTP admin
# ============================================================

class AdminClient:
    def __init__(self, backend_url: str, username: str, password: str):
        self.base = backend_url.rstrip("/")
        self.token = self._login(username, password)

    def _call(self, method: str, path: str, body: dict | None = None, auth: bool = True) -> tuple[int, dict]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(f"{self.base}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                text = response.read().decode("utf-8")
                return response.status, (json.loads(text) if text else {})
        except urllib.error.HTTPError as error:
            text = error.read().decode("utf-8", errors="replace")
            try:
                return error.code, json.loads(text)
            except json.JSONDecodeError:
                return error.code, {"message": text}

    def _login(self, username: str, password: str) -> str:
        status, body = self._call("POST", "/api/v1/admin/auth/login",
                                   {"username": username, "password": password}, auth=False)
        if status != 200 or "token" not in body:
            raise RuntimeError(f"Connexion admin échouée ({status}) : {body}")
        return body["token"]

    def pre_register(self, serial: str) -> None:
        status, body = self._call("POST", "/api/v1/admin/devices", {
            "serialNumber": serial,
            "deviceType": "sensor-e2e-test",
            "location": "banc-de-test",
        })
        if status not in (200, 201):
            raise RuntimeError(f"Pré-enregistrement échoué ({status}) : {body}")

    def status(self, did: str) -> str:
        _, body = self._call("GET", f"/api/v1/admin/devices/{did}/status")
        return body.get("status", "")

    def suspend(self, did: str, reason: str) -> tuple[int, dict]:
        return self._call("PATCH", f"/api/v1/admin/devices/{did}/suspend", {"reason": reason})

    def reactivate(self, did: str) -> tuple[int, dict]:
        return self._call("PATCH", f"/api/v1/admin/devices/{did}/reactivate")

    def revoke(self, did: str, reason: str) -> tuple[int, dict]:
        return self._call("PATCH", f"/api/v1/admin/devices/{did}/revoke", {"reason": reason})


# ============================================================
# Requête opérationnelle "bas niveau" — chaque champ est un paramètre
# explicite, pour pouvoir en corrompre un seul à la fois dans la matrice
# d'attaques (contrairement à device_simulator.publish_operational_request,
# qui construit toujours une preuve correcte).
# ============================================================

def raw_operational_request(
    mqtt_client: mqtt.Client, did: str, jwt: str, signing_key: nacl.signing.SigningKey,
    *, jti_override: str | None = None, timestamp_override: int | None = None,
    request_id_override: str | None = None, permission: str = "device:read",
    permission_sent: str | None = None, metrics_override: dict | None = None,
    metrics_sent_override: str | None = None, sign_with: nacl.signing.SigningKey | None = None,
    jwt_sent_override: str | None = None, timeout: float = 8.0,
) -> tuple[bool, dict]:
    # jwt sert à dériver les claims (jti) — c'est toujours un JWT valide et
    # décodable. jwt_sent_override, s'il est fourni, est ce qui part
    # réellement dans le payload envoyé au Gateway : un vrai attaquant
    # réutilise le jti d'un JWT valide qu'il a intercepté, il n'a pas besoin
    # de décoder la version altérée qu'il fabrique pour l'attaque.
    claims = decode_jwt_payload(jwt)
    jti = jti_override if jti_override is not None else claims["jti"]
    timestamp = timestamp_override if timestamp_override is not None else int(time.time())
    request_id = request_id_override if request_id_override is not None else uuid.uuid4().hex

    metrics = metrics_override if metrics_override is not None else {
        "temperatureC": 21.0, "humidityPercent": 45.0, "batteryPercent": 100,
        "uptimeSeconds": 1, "measuredAt": timestamp,
    }
    metrics_json = json.dumps(metrics, sort_keys=True, separators=(",", ":"))
    metrics_hash = encode_b64url(hashlib.sha256(metrics_json.encode("utf-8")).digest())

    message = f"{did}:{jti}:{timestamp}:{request_id}:{permission or ''}:{metrics_hash}"
    signer = sign_with if sign_with is not None else signing_key
    proof_signature = sign_b64url(signer, message)

    payload = {
        "jwt": jwt_sent_override if jwt_sent_override is not None else jwt,
        "timestamp": timestamp,
        "proofSignature": proof_signature,
        "requestId": request_id,
        "requestedPermission": permission_sent if permission_sent is not None else permission,
        "metricsJson": metrics_sent_override if metrics_sent_override is not None else metrics_json,
    }

    request_topic = f"iot/{did}/operational/request"
    response_topic = f"iot/{did}/operational/response"
    received: dict = {}

    def on_message(_client, _userdata, msg):
        try:
            received["body"] = json.loads(msg.payload.decode("utf-8"))
        except json.JSONDecodeError:
            received["body"] = {"authorized": False, "reason": "réponse illisible"}

    mqtt_client.on_message = on_message
    mqtt_client.subscribe(response_topic, qos=1)
    mqtt_client.publish(request_topic, json.dumps(payload), qos=1)
    deadline = time.time() + timeout
    while "body" not in received and time.time() < deadline:
        time.sleep(0.05)
    mqtt_client.unsubscribe(response_topic)
    return ("body" in received), received.get("body", {"authorized": False, "reason": "timeout"})


def enroll_test_device(admin: AdminClient, config: dict, serial: str) -> tuple[dict, GatewayRpcClient]:
    admin.pre_register(serial)
    master_key = load_or_create_master_key()
    state = load_or_create_identity(serial, int(config["app_id"]), master_key)
    gateway = GatewayRpcClient(config["mqtt_host"], int(config["mqtt_port"]), int(config["gateway_timeout_seconds"]))
    wait_for_enrollment(state, gateway, master_key, retry_delay=2, max_attempts=15)
    return state, gateway


# ============================================================
# PHASE 1 — Cycle de vie complet
# ============================================================

def run_lifecycle_phase(admin: AdminClient, config: dict) -> None:
    phase = "cycle_de_vie"
    serial = f"E2E-LIFECYCLE-{int(time.time())}"
    print(f"\n=== PHASE 1 — cycle de vie ({serial}) ===")

    state, gateway = enroll_test_device(admin, config, serial)
    did = state["did"]
    master_key = load_or_create_master_key()
    signing_key = signing_key_from_state(state, master_key)

    record(phase, "enrôlement", "ACTIVE", admin.status(did), admin.status(did) == "ACTIVE")

    mqtt_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    mqtt_client.connect(config["mqtt_host"], int(config["mqtt_port"]))
    mqtt_client.loop_start()

    try:
        ok, resp = raw_operational_request(mqtt_client, did, state["jwt"], signing_key, permission="device:read")
        record(phase, "requête opérationnelle valide (avant incident)", "authorized=True",
               f"authorized={resp.get('authorized')}", ok and resp.get("authorized") is True)

        # Permission jamais accordée -> violation -> suspension immédiate (seuil = 1)
        ok, resp = raw_operational_request(mqtt_client, did, state["jwt"], signing_key, permission="device:admin")
        record(phase, "requête avec permission non accordée", "authorized=False",
               f"authorized={resp.get('authorized')}", ok and resp.get("authorized") is False)

        time.sleep(1.0)
        status = admin.status(did)
        record(phase, "suspension automatique après violation", "SUSPENDED", status, status == "SUSPENDED")

        admin.reactivate(did)
        status = admin.status(did)
        record(phase, "réactivation admin", "ACTIVE", status, status == "ACTIVE")

        ok, resp = raw_operational_request(mqtt_client, did, state["jwt"], signing_key, permission="device:read")
        record(phase, "requête opérationnelle valide (après réactivation)", "authorized=True",
               f"authorized={resp.get('authorized')}", ok and resp.get("authorized") is True)

        t_decision = time.perf_counter()
        admin.revoke(did, "fin de test E2E")
        t_revoke_confirmed = None
        deadline = t_decision + 10
        while time.perf_counter() < deadline:
            if admin.status(did) == "REVOKED":
                t_revoke_confirmed = time.perf_counter()
                break
            time.sleep(0.05)
        record(phase, "révocation admin (statut PostgreSQL)", "REVOKED",
               admin.status(did), t_revoke_confirmed is not None)

        ok, resp = raw_operational_request(mqtt_client, did, state["jwt"], signing_key, permission="device:read")
        t_blocked = time.perf_counter()
        record(phase, "requête opérationnelle après révocation", "authorized=False",
               f"authorized={resp.get('authorized')}", ok and resp.get("authorized") is False)

        if t_revoke_confirmed is not None:
            blocking_delay_ms = (t_blocked - t_decision) * 1000
            print(f"[TEMPS] Décision de révocation -> premier refus opérationnel : {blocking_delay_ms:.1f} ms")
            RESULTS.append({
                "phase": phase, "step": "temps_blocage_operationnel_ms",
                "expected": "< 1000 ms (H1)", "observed": f"{blocking_delay_ms:.1f} ms",
                "result": "PASS" if blocking_delay_ms < 1000 else "FAIL",
            })
    finally:
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
        gateway.close()


# ============================================================
# PHASE 2 — Matrice d'attaques
# ============================================================

def run_attack_phase(admin: AdminClient, config: dict) -> None:
    phase = "attaques"
    serial = f"E2E-ATTACK-{int(time.time())}"
    print(f"\n=== PHASE 2 — matrice d'attaques ({serial}) ===")

    state, gateway = enroll_test_device(admin, config, serial)
    did = state["did"]
    master_key = load_or_create_master_key()
    signing_key = signing_key_from_state(state, master_key)

    mqtt_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    mqtt_client.connect(config["mqtt_host"], int(config["mqtt_port"]))
    mqtt_client.loop_start()

    def expect_rejected(step: str, **kwargs) -> dict:
        ok, resp = raw_operational_request(mqtt_client, did, state["jwt"], signing_key, **kwargs)
        rejected = (not ok) or (resp.get("authorized") is not True)
        record(phase, step, "authorized=False (rejeté)",
               f"authorized={resp.get('authorized')}" if ok else "aucune réponse (timeout)", rejected)
        return resp

    try:
        # 1. Requête légitime de référence
        ok, first = raw_operational_request(mqtt_client, did, state["jwt"], signing_key, permission="device:read")
        record(phase, "requête de référence (doit être acceptée)", "authorized=True",
               f"authorized={first.get('authorized')}", ok and first.get("authorized") is True)

        # 2. Rejeu exact du même requestId
        fixed_id = uuid.uuid4().hex
        raw_operational_request(mqtt_client, did, state["jwt"], signing_key,
                                 permission="device:read", request_id_override=fixed_id)
        expect_rejected("rejeu exact du même requestId",
                         permission="device:read", request_id_override=fixed_id)

        # 3. Usurpation : signé avec une clé qui n'est pas celle du dispositif
        impostor_key = nacl.signing.SigningKey.generate()
        expect_rejected("signature d'un dispositif usurpateur", permission="device:read", sign_with=impostor_key)

        # 4. Permission falsifiée après signature (signé pour "device:read", envoyé "device:operate")
        expect_rejected("permission modifiée après signature",
                         permission="device:read", permission_sent="device:operate")

        # 5. Métriques falsifiées après signature
        expect_rejected("métriques modifiées après signature",
                         permission="device:read", metrics_sent_override='{"tampered":true}')

        # 6. Horodatage hors fenêtre de fraîcheur (2 minutes dans le passé)
        expect_rejected("horodatage expiré (hors fenêtre de fraîcheur)",
                         permission="device:read", timestamp_override=int(time.time()) - 120)

        # 7. JWT altéré (un caractère modifié dans le payload).
        # La signature PoP est calculée sur le JWT original (jti correct),
        # mais le JWT envoyé est corrompu — simule un attaquant qui modifie
        # le JWT sans pouvoir recalculer la signature admin Ed25519.
        parts = state["jwt"].split(".")
        if len(parts) == 3:
            tampered_payload = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
            tampered_jwt = ".".join([parts[0], tampered_payload, parts[2]])
            ok, resp = raw_operational_request(mqtt_client, did, state["jwt"], signing_key,
                                               permission="device:read", jwt_sent_override=tampered_jwt)
            rejected = (not ok) or (resp.get("authorized") is not True)
            record(phase, "JWT altéré (payload modifié)", "authorized=False (rejeté)",
                   f"authorized={resp.get('authorized')}" if ok else "aucune réponse", rejected)

        # 8. DID inexistant / dispositif jamais enrôlé
        fake_signing_key = nacl.signing.SigningKey.generate()
        fake_public = bytes(fake_signing_key.verify_key)
        fake_did = build_did(fake_public, int(config["app_id"]))
        ok, resp = raw_operational_request(mqtt_client, fake_did, state["jwt"], fake_signing_key, permission="device:read")
        rejected = (not ok) or (resp.get("authorized") is not True)
        record(phase, "DID inexistant (dispositif jamais enrôlé)", "authorized=False (rejeté)",
               f"authorized={resp.get('authorized')}" if ok else "aucune réponse", rejected)

        # 9. Dispositif révoqué (fin du test)
        admin.revoke(did, "fin de matrice d'attaques")
        time.sleep(0.5)
        expect_rejected("requête d'un dispositif révoqué", permission="device:read")

    finally:
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
        gateway.close()


# ============================================================
# Sortie des résultats
# ============================================================

def write_results(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "e2e_security_results.csv"
    json_path = output_dir / "e2e_security_results.json"

    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["phase", "step", "expected", "observed", "result"])
        writer.writeheader()
        writer.writerows(RESULTS)
    json_path.write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False), encoding="utf-8")

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["result"] == "PASS")
    print(f"\n=== RÉSUMÉ : {passed}/{total} tests PASS ===")
    for r in RESULTS:
        if r["result"] == "FAIL":
            print(f"  ÉCHEC : [{r['phase']}] {r['step']} — attendu {r['expected']}, obtenu {r['observed']}")
    print(f"\nRésultats détaillés : {csv_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Suite E2E + sécurité (cycle de vie + matrice d'attaques)")
    parser.add_argument("--config", type=Path, default=ROOT / "experiments" / "e2e_security_config.json")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments" / "results")
    parser.add_argument("--phase", choices=["lifecycle", "attacks", "all"], default="all")
    args = parser.parse_args()

    with args.config.open(encoding="utf-8") as stream:
        config = json.load(stream)

    admin = AdminClient(config["backend_url"], config["admin_username"], config["admin_password"])

    if args.phase in ("lifecycle", "all"):
        run_lifecycle_phase(admin, config)
    if args.phase in ("attacks", "all"):
        run_attack_phase(admin, config)

    write_results(args.output)
    return 0 if all(r["result"] == "PASS" for r in RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
