"""Repeatable performance benchmark for the IoT operational path.

The device must already be enrolled and have a valid JWT in its state file.
This benchmark measures MQTT through Node-RED with a Redis cache HIT, MQTT
with a forced cache MISS, and direct HTTP calls to the backend.
"""

import argparse
import csv
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "devices"))
from device_simulator import decode_jwt_payload, load_or_create_master_key, sign_b64url, signing_key_from_state  # noqa: E402


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def http_post(url: str, payload: dict, timeout: float) -> tuple[int, dict]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8")
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = {"message": body}
        return error.code, body


def clear_cache(config: dict, did: str) -> None:
    key = f"device:{did}"
    result = subprocess.run(
        ["docker", "exec", config["redis_container"], "redis-cli", "DEL", key],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Impossible de vider Redis: {result.stderr.strip()}")


def operational_payload(state: dict, signing_key, permission: str) -> dict:
    claims = decode_jwt_payload(state["jwt"])
    timestamp = int(time.time())
    return {
        "did": state["did"],
        "jwt": state["jwt"],
        "timestamp": timestamp,
        "proofSignature": sign_b64url(signing_key, f"{claims['jti']}:{timestamp}"),
        "requestedPermission": permission,
        "metrics": {
            "temperatureC": 22.5,
            "humidityPercent": 50.0,
            "batteryPercent": 99,
            "uptimeSeconds": 1,
            "measuredAt": timestamp,
        },
    }


def mqtt_request(client: mqtt.Client, request_topic: str, response_topic: str, payload: dict, timeout: float) -> tuple[bool, dict]:
    received = {}

    def on_message(_client, _userdata, message):
        try:
            received["body"] = json.loads(message.payload.decode("utf-8"))
        except json.JSONDecodeError:
            received["body"] = {"ok": False, "message": "Réponse JSON invalide"}

    client.on_message = on_message
    client.subscribe(response_topic, qos=1)
    info = client.publish(request_topic, json.dumps(payload), qos=1)
    info.wait_for_publish(timeout=timeout)
    deadline = time.perf_counter() + timeout
    while "body" not in received and time.perf_counter() < deadline:
        time.sleep(0.01)
    return "body" in received, received.get("body", {})


def run_scenario(config: dict, state: dict, signing_key, scenario: str, rows: list[dict]) -> None:
    did = state["did"]
    timeout = float(config["response_timeout_seconds"])
    request_topic = f"iot/{did}/operational/request"
    response_topic = f"iot/{did}/operational/response"
    direct_url = f"{config['backend_url'].rstrip('/')}/api/v1/operational/verify"

    client = None
    if scenario.startswith("mqtt"):
        client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        client.connect(config["mqtt_host"], int(config["mqtt_port"]))
        client.loop_start()

    try:
        for repetition in range(1, int(config["repetitions"]) + 1):
            for sequence in range(1, int(config["requests_per_scenario"]) + 1):
                if scenario == "mqtt_miss":
                    clear_cache(config, did)
                payload = operational_payload(state, signing_key, config["permission"])
                started = time.perf_counter()
                if scenario.startswith("mqtt"):
                    ok, response = mqtt_request(client, request_topic, response_topic, payload, timeout)
                    success = ok and bool(response.get("authorized") or response.get("ok"))
                else:
                    status, response = http_post(direct_url, payload, timeout)
                    success = status == 200 and bool(response.get("authorized"))
                elapsed_ms = (time.perf_counter() - started) * 1000
                rows.append({
                    "scenario": scenario,
                    "repetition": repetition,
                    "sequence": sequence,
                    "success": int(success),
                    "latency_ms": round(elapsed_ms, 3),
                    "status": response.get("status", "") if isinstance(response, dict) else "",
                    "authorized": response.get("authorized", response.get("ok", False)) if isinstance(response, dict) else False,
                    "did": did,
                })
                time.sleep(float(config["interval_seconds"]))
    finally:
        if client is not None:
            client.loop_stop()
            client.disconnect()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def write_results(output_dir: Path, rows: list[dict]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = output_dir / "benchmark_raw.csv"
    with raw_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    summaries = []
    for scenario in sorted({row["scenario"] for row in rows}):
        selected = [row for row in rows if row["scenario"] == scenario]
        latencies = [float(row["latency_ms"]) for row in selected]
        successes = sum(int(row["success"]) for row in selected)
        summaries.append({
            "scenario": scenario,
            "requests": len(selected),
            "successes": successes,
            "success_rate_percent": round(successes * 100 / len(selected), 2),
            "average_latency_ms": round(sum(latencies) / len(latencies), 3),
            "p50_latency_ms": round(percentile(latencies, 0.50), 3),
            "p95_latency_ms": round(percentile(latencies, 0.95), 3),
            "p99_latency_ms": round(percentile(latencies, 0.99), 3),
            "min_latency_ms": round(min(latencies), 3),
            "max_latency_ms": round(max(latencies), 3),
        })
    summary_path = output_dir / "benchmark_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=summaries[0].keys())
        writer.writeheader()
        writer.writerows(summaries)
    print(f"Résultats bruts : {raw_path}")
    print(f"Résumé chapitre 5 : {summary_path}")
    for summary in summaries:
        print(json.dumps(summary, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark MQTT/Node-RED/Backend IoT")
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
    rows = []
    for scenario in config["scenarios"]:
        if scenario not in {"mqtt_hit", "mqtt_miss", "backend_direct"}:
            raise ValueError(f"Scénario inconnu: {scenario}")
        print(f"Démarrage du scénario {scenario}...")
        run_scenario(config, state, signing_key, scenario, rows)
    write_results(args.output, rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
