#!/usr/bin/env python3
"""Test d'intégration système complet (équivalent de run_integration.ps1).

Usage :
    python experiments/run_integration.py [options]
"""
import argparse
import datetime
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

results = []


def add_result(step: str, passed: bool, detail: str) -> None:
    results.append({"step": step, "result": "PASS" if passed else "FAIL", "detail": detail})
    print(f"[{'PASS' if passed else 'FAIL'}] {step} — {detail}")


def invoke_step(name: str, action) -> bool:
    print(f"\n=== {name} ===")
    try:
        action()
        add_result(name, True, "OK")
        return True
    except Exception as exc:  # noqa: BLE001
        add_result(name, False, str(exc))
        return False


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Commande requise introuvable: {name}")


def run(cmd, cwd, log_path: Path | None = None, check=True) -> None:
    print(f"$ {' '.join(str(c) for c in cmd)}")
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w", encoding="utf-8", errors="replace") as stream:
            proc = subprocess.run(cmd, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
    else:
        proc = subprocess.run(cmd, cwd=cwd, shell=(os.name == "nt"))
    if check and proc.returncode != 0:
        raise RuntimeError(f"Commande échouée ({proc.returncode}): {cmd[0]}")


def wait_http(uri: str, timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(uri, timeout=5) as response:
                if 200 <= response.status < 500:
                    return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(2)
    raise RuntimeError(f"Timeout en attendant {uri}")


def test_tcp_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Test d'intégration système complet")
    parser.add_argument("--skip-unit-tests", action="store_true")
    parser.add_argument("--skip-contract", action="store_true")
    parser.add_argument("--skip-e2e", action="store_true")
    parser.add_argument("--skip-frontend", action="store_true")
    parser.add_argument("--no-start-infrastructure", action="store_true")
    parser.add_argument("--no-start-backend", action="store_true")
    parser.add_argument("--keep-backend", action="store_true")
    parser.add_argument("--backend-timeout", type=int, default=120)
    parser.add_argument("--output-dir", default=str(ROOT / "experiments" / "results" / "integration"))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    backend_process: subprocess.Popen | None = None

    try:
        print("IoT Auth — test d'intégration système complet")
        print(f"Racine    : {ROOT}")
        print(f"Rapports  : {output_dir}")

        def prereqs():
            for cmd in ("docker", "python", "algokit", "git"):
                require_command(cmd)
            if not (ROOT / "backend" / "mvnw.cmd").exists():
                raise RuntimeError("backend/mvnw.cmd introuvable")
            if not (ROOT / "experiments" / "e2e_security_suite.py").exists():
                raise RuntimeError("experiments/e2e_security_suite.py introuvable")

        invoke_step("Prérequis locaux", prereqs)

        if not args.no_start_infrastructure:
            invoke_step("Démarrage PostgreSQL/Redis", lambda: run(
                ["docker", "compose", "-f", "compose.yaml", "up", "-d", "postgres", "redis"],
                cwd=ROOT / "backend"))
            invoke_step("Démarrage Mosquitto/Node-RED", lambda: run(
                ["docker", "compose", "up", "-d", "--build"], cwd=ROOT / "gateway"))
            invoke_step("Démarrage/validation Algorand LocalNet", lambda: run(
                ["algokit", "localnet", "start"], cwd=ROOT))

        def infra_up():
            for host, port, name in [("127.0.0.1", 5432, "PostgreSQL"), ("127.0.0.1", 6379, "Redis"),
                                     ("127.0.0.1", 1883, "Mosquitto"), ("127.0.0.1", 1880, "Node-RED"),
                                     ("127.0.0.1", 4001, "Algod")]:
                if not test_tcp_port(host, port):
                    raise RuntimeError(f"{name}:{port} indisponible")

        invoke_step("Disponibilité infrastructure", infra_up)

        if not args.skip_unit_tests:
            invoke_step("Tests Maven backend", lambda: run(
                [str(ROOT / "backend" / "mvnw.cmd"), "test"],
                cwd=ROOT / "backend", log_path=output_dir / "maven-test.log"))

        if not args.skip_contract:
            def contract_test():
                if not os.environ.get("ALGORAND_DEPLOYER_MNEMONIC"):
                    raise RuntimeError("Définir ALGORAND_DEPLOYER_MNEMONIC pour le test LocalNet.")
                run([sys.executable, "test_contract_irreversibility.py"],
                    cwd=ROOT / "smart-contract", log_path=output_dir / "contract-test.log")

            invoke_step("Test d'irréversibilité du smart contract", contract_test)

        if not args.no_start_backend:
            def start_backend():
                nonlocal backend_process
                if not os.environ.get("IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD"):
                    raise RuntimeError("Définir IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD avant le lancement.")
                log_path = output_dir / "backend.log"
                with open(log_path, "w", encoding="utf-8", errors="replace") as stream:
                    backend_process = subprocess.Popen(
                        [str(ROOT / "backend" / "mvnw.cmd"), "spring-boot:run",
                         "-Dspring-boot.run.profiles=dev"],
                        cwd=ROOT / "backend", stdout=stream, stderr=subprocess.STDOUT,
                    )
                try:
                    wait_http("http://localhost:8083/actuator/health", args.backend_timeout)
                except Exception:
                    if log_path.exists():
                        print("\n--- backend.log (fin) ---")
                        print("\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-100:]))
                    raise

            invoke_step("Démarrage backend Spring Boot", start_backend)
        else:
            invoke_step("Validation backend déjà démarré",
                        lambda: wait_http("http://localhost:8083/actuator/health", 10))

        if not args.skip_e2e:
            def e2e():
                if not os.environ.get("IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD"):
                    raise RuntimeError("Définir IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD avant la suite E2E.")
                base_config = json.loads((ROOT / "experiments" / "e2e_security_config.json").read_text(encoding="utf-8"))
                base_config["admin_password"] = os.environ["IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD"]
                runtime_config = output_dir / "e2e_security_config.runtime.json"
                runtime_config.write_text(json.dumps(base_config, indent=2, ensure_ascii=False), encoding="utf-8")
                run([sys.executable, str(ROOT / "experiments" / "e2e_security_suite.py"),
                     "--config", str(runtime_config),
                     "--output", str(ROOT / "experiments" / "results"),
                     "--phase", "all"],
                    cwd=ROOT, log_path=output_dir / "e2e-security.log")

            invoke_step("Suite E2E cycle de vie + attaques", e2e)

        if not args.skip_frontend:
            def frontend():
                if not (ROOT / "frontend" / "node_modules").exists():
                    run(["npm", "ci"], cwd=ROOT / "frontend")
                run(["npm", "run", "lint"], cwd=ROOT / "frontend")
                run(["npm", "run", "build"], cwd=ROOT / "frontend")

            invoke_step("Lint + build frontend", frontend)

        failed = [r for r in results if r["result"] == "FAIL"]
        summary = {
            "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "git_commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                         capture_output=True, text=True).stdout.strip(),
            "passed": sum(1 for r in results if r["result"] == "PASS"),
            "failed": len(failed),
            "status": "PASS" if not failed else "FAIL",
            "checks": results,
        }
        summary_path = output_dir / "integration_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

        print("\n========================================")
        print(f"RÉSULTAT GLOBAL : {summary['status']}")
        print(f"Contrôles PASS  : {summary['passed']}")
        print(f"Contrôles FAIL  : {summary['failed']}")
        print(f"Rapport         : {summary_path}")
        print("========================================")

        return 1 if failed else 0
    finally:
        if backend_process is not None and backend_process.poll() is None and not args.keep_backend:
            print("\nArrêt du backend Spring Boot...")
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(backend_process.pid)],
                                   capture_output=True)
                else:
                    backend_process.terminate()
                backend_process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                backend_process.kill()


if __name__ == "__main__":
    sys.exit(main())
