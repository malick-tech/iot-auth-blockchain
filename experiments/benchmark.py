"""Benchmark de latence operationnelle IoT Auth (protocole v2).

The device must already be enrolled and have a valid JWT in its state file.
This benchmark measures MQTT through Node-RED with a Redis cache HIT, MQTT
with a forced cache MISS, and direct HTTP calls to the backend.

Protocole v2 : attente par evenement threading.Event, abonnement MQTT une fois,
echauffement exclu, scenarios entrelaces par blocs ordre randomise, etalon
mqtt_echo_floor, statistiques mediane + IC95 bootstrap + Mann-Whitney U.

Le rate limiting DOIT etre desactive (IOT_AUTH_RATE_LIMIT_ENABLED=false).
"""

import argparse
import csv
import datetime
import platform
import random
import threading
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "devices"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from benchmark_stats import (  # noqa: E402
    holm_adjust,
    mann_whitney_u,
    paired_cluster_reduction_percent,
    paired_sign_flip_test,
    summarize,
)
from device_simulator import (  # noqa: E402
    decode_jwt_payload,
    hash_metrics_json,
    load_or_create_master_key,
    sign_b64url,
    signing_key_from_state,
)


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def http_post(url: str, payload: dict, timeout: float,
              connection: "http.client.HTTPConnection | None" = None) -> tuple[int, dict]:
    body_bytes = json.dumps(payload).encode("utf-8")
    if connection is not None:
        parsed = urllib.parse.urlsplit(url)
        p = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        connection.request("POST", p, body=body_bytes,
                           headers={"Content-Type": "application/json", "Connection": "keep-alive"})
        resp = connection.getresponse()
        raw = resp.read()
        if resp.status == 200:
            text = raw.decode("utf-8")
            return resp.status, json.loads(text) if text else {}
        text = raw.decode("utf-8", errors="replace")
        try:
            return resp.status, json.loads(text)
        except json.JSONDecodeError:
            return resp.status, {"message": text}

    req = urllib.request.Request(url, data=body_bytes,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as err:
        raw = err.read()
        body = raw.decode("utf-8", errors="replace")
        try:
            return err.code, json.loads(body)
        except json.JSONDecodeError:
            return err.code, {"message": body}


def clear_cache(config: dict, did: str) -> None:
    key = f"device:{did}"
    password = os.environ.get("REDIS_PASSWORD")
    if not password:
        raise RuntimeError("REDIS_PASSWORD doit etre defini pour vider le cache Redis du benchmark")
    result = subprocess.run(
        ["docker", "exec", "-e", f"REDISCLI_AUTH={password}",
         config["redis_container"], "redis-cli", "DEL", key],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0 and not result.stdout.strip().isdigit():
        raise RuntimeError(f"Redis a refuse DEL {key}: {result.stdout.strip()}")
    if result.returncode != 0:
        raise RuntimeError(f"Impossible de vider Redis: {result.stderr.strip()}")


def operational_payload(state: dict, signing_key, permission: str) -> dict:
    claims = decode_jwt_payload(state["jwt"])
    timestamp = int(time.time())
    request_id = uuid.uuid4().hex
    metrics = {
        "temperatureC": 22.5, "humidityPercent": 50.0, "batteryPercent": 99,
        "uptimeSeconds": 1, "measuredAt": timestamp,
    }
    metrics_json = json.dumps(metrics, sort_keys=True, separators=(",", ":"))
    metrics_hash = hash_metrics_json(metrics_json)
    message = f"{state['did']}:{claims['jti']}:{timestamp}:{request_id}:{permission or ''}:{metrics_hash}"
    return {
        "did": state["did"], "jwt": state["jwt"], "timestamp": timestamp,
        "requestId": request_id, "proofSignature": sign_b64url(signing_key, message),
        "requestedPermission": permission, "metricsJson": metrics_json,
    }


VALID_SCENARIOS = {"mqtt_hit", "mqtt_miss", "backend_direct", "mqtt_echo_floor"}
COMPARISONS = [
    ("mqtt_hit", "mqtt_miss"),
    ("mqtt_hit", "backend_direct"),
    ("mqtt_miss", "backend_direct"),
]


class MqttRpc:
    """Client MQTT requete/reponse a un seul vol : abonnement fait une fois, attente par evenement."""

    def __init__(self, host: str, port: int, response_topic: str, timeout: float):
        self.timeout = timeout
        self.response_topic = response_topic
        self._arrived = threading.Event()
        self._subscribed = threading.Event()
        self._body: dict = {}
        self._t_arrival = 0.0
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_message = self._on_message
        self.client.on_subscribe = lambda *a, **k: self._subscribed.set()
        self.client.connect(host, port)
        sock = self.client.socket()
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.client.loop_start()
        self.client.subscribe(response_topic, qos=1)
        if not self._subscribed.wait(timeout):
            raise RuntimeError(f"SUBACK non recu pour {response_topic}")

    def _on_message(self, _client, _userdata, message):
        t = time.perf_counter()
        try:
            body = json.loads(message.payload.decode("utf-8"))
        except json.JSONDecodeError:
            body = {"ok": False, "message": "Reponse JSON invalide"}
        if not self._arrived.is_set():
            self._body, self._t_arrival = body, t
            self._arrived.set()

    def request(self, request_topic: str, payload: dict) -> tuple[bool, dict, float]:
        self._arrived.clear()
        data = json.dumps(payload)
        t0 = time.perf_counter()
        self.client.publish(request_topic, data, qos=1)
        got = self._arrived.wait(self.timeout)
        latency_ms = (self._t_arrival - t0) * 1000 if got else (time.perf_counter() - t0) * 1000
        return got, (self._body if got else {}), latency_ms

    def close(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()


class Runner:
    """Un contexte par scenario (connexion ouverte une fois)."""

    def __init__(self, config: dict, state: dict, signing_key, scenario: str):
        self.config, self.state, self.key, self.scenario = config, state, signing_key, scenario
        self.did = state["did"]
        timeout = float(config["response_timeout_seconds"])
        self.rpc = None
        self.connection = None
        self.request_topic = f"iot/{self.did}/operational/request"
        if scenario in ("mqtt_hit", "mqtt_miss"):
            self.rpc = MqttRpc(config["mqtt_host"], int(config["mqtt_port"]),
                               f"iot/{self.did}/operational/response", timeout)
        elif scenario == "mqtt_echo_floor":
            echo = f"bench/echo/{uuid.uuid4().hex}"
            self.request_topic = echo
            self.rpc = MqttRpc(config["mqtt_host"], int(config["mqtt_port"]), echo, timeout)
        else:
            parsed = urllib.parse.urlsplit(config["backend_url"])
            self.connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
            self.direct_url = f"{config['backend_url'].rstrip('/')}/api/v1/operational/verify"
        self.timeout = timeout

    def one(self) -> tuple[bool, float, str]:
        if self.scenario == "mqtt_echo_floor":
            got, _body, latency = self.rpc.request(self.request_topic, {"ping": time.time()})
            return got, latency, "" if got else "timeout"
        if self.scenario == "mqtt_miss":
            clear_cache(self.config, self.did)
        payload = operational_payload(self.state, self.key, self.config["permission"])
        if self.rpc is not None:
            got, body, latency = self.rpc.request(self.request_topic, payload)
            ok = got and bool(body.get("authorized") or body.get("ok"))
            if ok:
                return True, latency, ""
            detail = "timeout" if not got else (body.get("reason") or body.get("message") or str(body)[:120])
            return False, latency, detail
        t0 = time.perf_counter()
        status, body = http_post(self.direct_url, payload, self.timeout, connection=self.connection)
        latency = (time.perf_counter() - t0) * 1000
        ok = status == 200 and isinstance(body, dict) and bool(body.get("authorized"))
        return ok, latency, "" if ok else f"HTTP {status}: {str(body)[:100]}"

    def close(self) -> None:
        if self.rpc:
            self.rpc.close()
        if self.connection:
            self.connection.close()


def run_benchmark(config: dict, state: dict, signing_key) -> tuple[list[dict], list[dict]]:
    scenarios = list(config["scenarios"])
    for sc in scenarios:
        if sc not in VALID_SCENARIOS:
            raise ValueError(f"Scenario inconnu: {sc}")
    interval = float(config["interval_seconds"])
    block = int(config["requests_per_block"])
    reps = int(config["repetitions"])
    warmup = int(config.get("warmup_requests", 30))
    rng = random.Random(int(config.get("seed", 2026)))

    runners = {sc: Runner(config, state, signing_key, sc) for sc in scenarios}
    rows: list[dict] = []
    failures: list[dict] = []
    try:
        for sc in scenarios:
            print(f"Echauffement {sc} ({warmup} requetes, exclues)...")
            for _ in range(warmup):
                runners[sc].one()
                time.sleep(interval)
        for rep in range(1, reps + 1):
            order = scenarios[:]
            rng.shuffle(order)
            print(f"Repetition {rep}/{reps} : ordre {order}")
            for sc in order:
                if sc == "mqtt_hit":
                    runners[sc].one()
                    time.sleep(interval)
                for seq in range(1, block + 1):
                    ok, latency, detail = runners[sc].one()
                    row = {"scenario": sc, "repetition": rep, "sequence": seq,
                           "success": int(ok), "latency_ms": round(latency, 3)}
                    rows.append(row)
                    if not ok:
                        failures.append({**row, "detail": detail})
                    time.sleep(interval)
    finally:
        for r in runners.values():
            r.close()
    return rows, failures


def write_results(output_dir: Path, rows: list[dict], failures: list[dict], config: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_path = output_dir / "benchmark_raw.csv"
    with raw_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    ok_latencies: dict[str, list[float]] = {}
    ok_by_rep: dict[str, dict[int, list[float]]] = {}
    summaries = []
    for scenario in sorted({r["scenario"] for r in rows}):
        # Ordre temporel conserve (repetition, sequence) : requis pour l'autocorrelation.
        selected = sorted((r for r in rows if r["scenario"] == scenario),
                          key=lambda r: (int(r["repetition"]), int(r["sequence"])))
        good = [float(r["latency_ms"]) for r in selected if int(r["success"])]
        ok_latencies[scenario] = good
        by_rep: dict[int, list[float]] = {}
        for r in selected:
            if int(r["success"]):
                by_rep.setdefault(int(r["repetition"]), []).append(float(r["latency_ms"]))
        ok_by_rep[scenario] = by_rep
        entry: dict = {
            "scenario": scenario,
            "requests": len(selected),
            "successes": len(good),
            "success_rate_percent": round(len(good) * 100 / len(selected), 2),
        }
        if len(good) >= 2:
            entry.update(summarize(good, [by_rep[k] for k in sorted(by_rep)]))
            entry["p99_reliable"] = int(len(good) >= 1000)
        summaries.append(entry)
    fieldnames = sorted(
        {k for s in summaries for k in s},
        key=lambda k: list(summaries[0]).index(k) if k in summaries[0] else 99,
    )
    with (output_dir / "benchmark_summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, restval="")
        writer.writeheader()
        writer.writerows(summaries)

    # Comparaisons : IC par bootstrap de blocs apparies (une repetition = une unite), test de
    # permutation par retournement de signe sur les medianes par repetition, puis correction
    # de Holm. Mann-Whitney sur observations brutes = descriptif (taille d'effet) seulement.
    # Convention : reduction > 0 => `fast` est reellement plus rapide que `slow` ;
    # reduction < 0 => l'hypothese de gain est INFIRMEE (fast est plus lent).
    comparisons = []
    for fast, slow in COMPARISONS:
        a, b = ok_latencies.get(fast, []), ok_latencies.get(slow, [])
        fa, sb = ok_by_rep.get(fast, {}), ok_by_rep.get(slow, {})
        if len(a) < 20 or len(b) < 20 or len(set(fa) & set(sb)) < 5:
            continue
        red, lo, hi, k = paired_cluster_reduction_percent(fa, sb)
        perm = paired_sign_flip_test(fa, sb)
        test = mann_whitney_u(a, b)
        comparisons.append({
            "fast": fast, "slow": slow, "n_fast": len(a), "n_slow": len(b), "n_blocks": k,
            "median_reduction_percent": round(red, 2),
            "reduction_block_ci95_low": round(lo, 2), "reduction_block_ci95_high": round(hi, 2),
            "mean_block_diff_ms": round(perm["mean_diff_ms"], 3),
            "blocks_slow_gt_fast": perm["n_positive"],
            "p_permutation": perm["p_value"],
            "mann_whitney_u": round(test["u"], 1),
            "p_mann_whitney_descriptive": f"{test['p_value']:.3e}",
            "rank_biserial": round(test["rank_biserial"], 3),
        })
    if comparisons:
        adjusted = holm_adjust([c["p_permutation"] for c in comparisons])
        for c, p_adj in zip(comparisons, adjusted):
            c["p_permutation_holm"] = round(p_adj, 5)
            c["p_permutation"] = round(c["p_permutation"], 5)
            c["gain_supported"] = int(c["reduction_block_ci95_low"] > 0 and p_adj < 0.05)
    if comparisons:
        with (output_dir / "benchmark_comparisons.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=comparisons[0].keys())
            writer.writeheader()
            writer.writerows(comparisons)

    # Toujours ecrire/supprimer : un ancien benchmark_failures.csv ne doit jamais survivre a
    # une campagne propre (sinon il contredit benchmark_summary.csv).
    failures_path = output_dir / "benchmark_failures.csv"
    if failures:
        with failures_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=failures[0].keys())
            writer.writeheader()
            writer.writerows(failures)
    elif failures_path.exists():
        failures_path.unlink()
        print("Ancien benchmark_failures.csv supprime (aucun echec dans cette campagne).")

    try:
        commit = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        ).stdout.strip()
    except OSError:
        commit = ""
    meta = {
        "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "git_commit": commit,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "perf_counter": {
            "implementation": time.get_clock_info("perf_counter").implementation,
            "resolution_s": time.get_clock_info("perf_counter").resolution,
            "monotonic": time.get_clock_info("perf_counter").monotonic,
        },
        "config": config,
        "limites": [
            "Un seul dispositif, requetes sequentielles : latence a vide, pas de debit.",
            "Observations autocorrelees (JIT, GC) : IC par bootstrap de blocs (repetitions) et test de permutation sur medianes par repetition ; n efficace dans benchmark_summary.csv.",
            "Benchmark execute avec rate limiting desactive.",
            "Clock/reseau locaux (loopback) : non representatif d'un reseau IoT reel.",
            "TCP_NODELAY active cote client de benchmark ; Mosquitto/Node-RED non verifies par ce script.",
        ],
    }
    (output_dir / "benchmark_meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"Resultats bruts : {raw_path}")
    for summary in summaries:
        print(json.dumps(summary, ensure_ascii=False))
    for comparison in comparisons:
        print(json.dumps(comparison, ensure_ascii=False))
    if failures:
        print(f"ATTENTION : {len(failures)} echecs (voir benchmark_failures.csv) ; premier : {failures[0]['detail']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark MQTT/Node-RED/Backend IoT Auth (v2)")
    parser.add_argument("--config", type=Path, default=ROOT / "experiments" / "benchmark_config.json")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments" / "results")
    args = parser.parse_args()

    config = load_config(args.config)
    state_path = ROOT / config["state_file"]
    with state_path.open(encoding="utf-8") as stream:
        state = json.load(stream)
    if not state.get("jwt") or not state.get("did"):
        raise RuntimeError("Le state file doit contenir un DID et un JWT valide.")
    if config.get("did") and config["did"] != state["did"]:
        raise RuntimeError("Le DID de benchmark ne correspond pas au state file.")

    master_key = load_or_create_master_key()
    signing_key = signing_key_from_state(state, master_key)
    rows, failures = run_benchmark(config, state, signing_key)
    write_results(args.output, rows, failures, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
