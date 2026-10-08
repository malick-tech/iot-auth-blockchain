"""Diagnostic des ~47 ms du chemin cache HIT : transport, Redis ou cryptographie ?

Principe : le flow Node-RED `gateway/node-red-data/diag_flow.json` (a importer dans Node-RED)
expose des etages isoles sur `iot/diag/<etage>/request` -> `iot/diag/<etage>/response`.
Chaque etage renvoie le temps passe DANS la fonction (`node_ms`, process.hrtime). Le script
mesure en parallele le temps aller-retour vu du client ; la difference (residu) est le
transport MQTT + l'ordonnancement Node-RED.

Etages :
  floor          client -> Mosquitto -> client (ne traverse PAS Node-RED), comme le benchmark
  echo           client -> Mosquitto -> Node-RED -> Mosquitto -> client, sans aucun travail
  sha256         hachage des metriques (etape 7 du HIT)
  redis          HGETALL d'une cle absente (etape « Lire cache device »)
  redis-set      SET NX PX (anti-rejeu, etape 7bis)
  verify1        1 verification Ed25519 avec tweetnacl (JS pur)
  verify         2 verifications Ed25519 avec tweetnacl (= ce que fait le HIT aujourd'hui)
  verify-native  2 verifications Ed25519 avec le module crypto natif de Node (alternative)

Usage (depuis la racine du depot, Node-RED et Mosquitto demarres) :
    python experiments/diagnose_gateway.py
    python experiments/diagnose_gateway.py --n 300 --interval 0.05

Sortie : tableau console + experiments/results/diagnose_gateway.csv.
Dependance : paho-mqtt (deja dans experiments/requirements.txt).
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import statistics
import subprocess
import threading
import time
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt

STAGES = ["echo", "sha256", "redis", "redis-set", "verify1", "verify", "verify-native"]


def pct(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    pos = (len(ordered) - 1) * fraction
    lo, hi = int(pos), min(int(pos) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


class Rpc:
    """Requete/reponse MQTT QoS 1, abonnement fait une fois (meme logique que benchmark.py)."""

    def __init__(self, host: str, port: int, timeout: float):
        self.timeout = timeout
        self._event = threading.Event()
        self._subscribed = threading.Event()
        self._body: dict = {}
        self._t_arrival = 0.0
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_message = self._on_message
        self.client.on_subscribe = lambda *a, **k: self._subscribed.set()
        self._connected = threading.Event()
        self._connect_rc = None

        def on_connect(_client, _userdata, _flags, reason_code, _properties=None):
            self._connect_rc = reason_code
            if not getattr(reason_code, "is_failure", False):
                self._connected.set()

        self.client.on_connect = on_connect
        try:
            self.client.connect(host, port)
        except OSError as exc:
            raise RuntimeError(
                f"Connexion TCP impossible vers {host}:{port} ({exc}). Mosquitto est-il demarre ?"
            ) from exc
        sock = self.client.socket()
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.client.loop_start()
        if not self._connected.wait(timeout):
            raise RuntimeError(
                f"Port {host}:{port} ouvert mais pas de CONNACK MQTT (reponse du broker : {self._connect_rc}). "
                "Ce n'est pas un broker Mosquitto operationnel : verifiez `docker ps` (Docker Desktop "
                "demarre ? conteneur iot-auth-mosquitto 'Up' ?)."
            )

    def subscribe(self, topic: str) -> None:
        self._subscribed.clear()
        self.client.subscribe(topic, qos=1)
        if not self._subscribed.wait(self.timeout):
            raise RuntimeError(f"SUBACK non recu pour {topic}")

    def _on_message(self, _client, _userdata, message):
        t = time.perf_counter()
        try:
            body = json.loads(message.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = {}
        if not self._event.is_set():
            self._body, self._t_arrival = body, t
            self._event.set()

    def call(self, topic: str, payload: dict) -> tuple[bool, dict, float]:
        self._event.clear()
        t0 = time.perf_counter()
        self.client.publish(topic, json.dumps(payload), qos=1)
        got = self._event.wait(self.timeout)
        rtt = ((self._t_arrival if got else time.perf_counter()) - t0) * 1000
        return got, (self._body if got else {}), rtt

    def close(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()


def docker_checks(container: str) -> list[str]:
    """Verifie (si docker est disponible) que set_tcp_nodelay est bien charge par Mosquitto."""
    notes: list[str] = []

    errors: list[str] = []

    def run(*args: str) -> str:
        try:
            out = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=15)
        except OSError as exc:
            errors.append(f"commande docker introuvable ({exc})")
            return ""
        except subprocess.TimeoutExpired:
            errors.append("docker ne repond pas (timeout 15 s)")
            return ""
        if out.returncode != 0 and out.stderr.strip():
            errors.append(out.stderr.strip().splitlines()[-1])
        return out.stdout.strip()

    conf = run("exec", container, "cat", "/mosquitto/config/mosquitto.conf")
    if not conf:
        detail = errors[-1] if errors else "sortie vide"
        return [f"Docker/conteneur '{container}' injoignable ({detail}) : verification Mosquitto ignoree.",
                "  -> verifiez `docker ps` et le nom exact du conteneur Mosquitto."]
    active = [ln.strip() for ln in conf.splitlines() if ln.strip().startswith("set_tcp_nodelay")]
    notes.append(f"mosquitto.conf dans le conteneur : {active[0] if active else 'set_tcp_nodelay ABSENT'}")
    started = run("inspect", "-f", "{{.State.StartedAt}}", container)
    notes.append(f"Conteneur Mosquitto demarre le : {started} (doit etre APRES la modification de la conf)")
    return notes


def measure(rpc: Rpc, topic_in: str, n: int, warmup: int, interval: float) -> tuple[list[float], list[float]]:
    rtts: list[float] = []
    inner: list[float] = []
    for i in range(warmup + n):
        ok, body, rtt = rpc.call(topic_in, {"i": i})
        if i >= warmup and ok:
            rtts.append(rtt)
            if "node_ms" in body:
                inner.append(float(body["node_ms"]))
        time.sleep(interval)
    return rtts, inner


def verdict(rows: dict[str, dict]) -> list[str]:
    """Heuristiques indicatives (seuils en ms) ; a confirmer par lecture du tableau."""
    out: list[str] = []
    echo = rows.get("echo", {}).get("rtt_median")
    floor = rows.get("floor", {}).get("rtt_median")
    verify = rows.get("verify", {}).get("node_median")
    native = rows.get("verify-native", {}).get("node_median")
    redis_set = rows.get("redis-set", {}).get("node_median")
    redis_get = rows.get("redis", {}).get("node_median")
    if echo is not None and floor is not None:
        if echo - floor > 15:
            out.append(f"TRANSPORT : echo via Node-RED = {echo:.1f} ms contre {floor:.1f} ms hors Node-RED. "
                       "Soupcon Nagle/ACK retarde ou reseau Docker : verifier set_tcp_nodelay et recreer Mosquitto.")
        else:
            out.append(f"Transport OK : echo via Node-RED = {echo:.1f} ms (plancher {floor:.1f} ms). "
                       "Le delai du HIT ne vient pas du transport MQTT.")
    if verify is not None:
        if verify > 10:
            out.append(f"CRYPTO : 2 verifications tweetnacl = {verify:.1f} ms dans la fonction."
                       + (f" Version native : {native:.2f} ms (gain x{verify / native:.0f})." if native else ""))
        else:
            out.append(f"Crypto non dominant : 2 verifications tweetnacl = {verify:.1f} ms.")
    redis_total = (redis_get or 0) + (redis_set or 0)
    if redis_total > 10:
        out.append(f"REDIS : HGETALL + SET NX = {redis_total:.1f} ms via host.docker.internal.")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--n", type=int, default=200, help="mesures par etage")
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--mosquitto-container", default="iot-auth-mosquitto")
    parser.add_argument("--output", default=str(Path(__file__).resolve().parent / "results" / "diagnose_gateway.csv"))
    args = parser.parse_args()

    for line in docker_checks(args.mosquitto_container):
        print(line)

    rows: dict[str, dict] = {}
    try:
        rpc = Rpc(args.host, args.port, args.timeout)
    except RuntimeError as exc:
        print(f"ERREUR : {exc}")
        return 1
    try:
        # Etage 'floor' : echo direct sur le broker, sans Node-RED.
        floor_topic = f"bench/echo/{uuid.uuid4().hex}"
        try:
            rpc.subscribe(floor_topic)
        except RuntimeError as exc:
            print(f"ERREUR : {exc}. Essayez --host 127.0.0.1 (conflit IPv6/IPv4 possible).")
            return 1
        rtts, _ = measure(rpc, floor_topic, args.n, args.warmup, args.interval)
        rows["floor"] = {"n": len(rtts), "rtt_median": statistics.median(rtts), "rtt_p95": pct(rtts, 0.95),
                         "node_median": None}

        for stage in STAGES:
            rpc.subscribe(f"iot/diag/{stage}/response")
            rtts, inner = measure(rpc, f"iot/diag/{stage}/request", args.n, args.warmup, args.interval)
            if not rtts:
                print(f"[{stage}] aucune reponse : le flow diag_flow.json est-il importe et deploye ?")
                continue
            rows[stage] = {
                "n": len(rtts),
                "rtt_median": statistics.median(rtts), "rtt_p95": pct(rtts, 0.95),
                "node_median": statistics.median(inner) if inner else None,
            }
    finally:
        rpc.close()

    header = f"{'etage':<14}{'n':>5}{'RTT med':>10}{'RTT p95':>10}{'dans fonction':>15}{'residu transport':>18}"
    print("\n" + header)
    print("-" * len(header))
    for stage, r in rows.items():
        node = r["node_median"]
        resid = (r["rtt_median"] - node) if node is not None else None
        r["residual"] = resid
        print(f"{stage:<14}{r['n']:>5}{r['rtt_median']:>10.2f}{r['rtt_p95']:>10.2f}"
              f"{(f'{node:.3f}' if node is not None else '-'):>15}"
              f"{(f'{resid:.2f}' if resid is not None else '-'):>18}")

    if not any(stage in rows for stage in STAGES):
        print("\nERREUR : aucun etage de diagnostic n'a repondu. Importez/deployez diag_flow.json "
              "(python experiments/nodered_admin.py ensure --flow gateway/node-red-data/diag_flow.json).")
        return 2

    print("\nLecture :")
    for line in verdict(rows):
        print(" -", line)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["stage", "n", "rtt_median_ms", "rtt_p95_ms", "node_median_ms", "residual_ms"])
        for stage, r in rows.items():
            writer.writerow([stage, r["n"], round(r["rtt_median"], 3), round(r["rtt_p95"], 3),
                             "" if r["node_median"] is None else round(r["node_median"], 4),
                             "" if r.get("residual") is None else round(r["residual"], 3)])
    print(f"\nResultats : {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())