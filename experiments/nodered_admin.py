"""Gestion de l'onglet de diagnostic Node-RED via l'API d'administration (sans interface).

Commandes :
    python experiments/nodered_admin.py ensure  --flow gateway/node-red-data/diag_flow.json
    python experiments/nodered_admin.py status
    python experiments/nodered_admin.py remove

`ensure` est idempotent : il importe l'onglet « DIAGNOSTIC latence » s'il est absent.
Codes de sortie : 0 = ok, 1 = erreur (message explicite sur stderr).
Bibliotheque standard uniquement.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

LABEL_PREFIX = "DIAGNOSTIC"


def call(method: str, url: str, body: object | None = None, timeout: float = 15.0):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json; charset=utf-8")
    request.add_header("Node-RED-API-Version", "v1")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else None


def explain(exc: Exception, url: str) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return (f"Node-RED refuse l'acces ({exc.code}) : adminAuth est active dans settings.js. "
                    "Importez diag_flow.json a la main (menu > Import).")
        return f"Node-RED a repondu HTTP {exc.code} sur {url}."
    return f"Node-RED injoignable sur {url} ({exc}). Le conteneur iot-auth-node-red est-il demarre ?"


def find_tab(base: str) -> dict | None:
    flows = call("GET", f"{base}/flows")
    if isinstance(flows, dict):  # API v2
        flows = flows.get("flows", [])
    for node in flows or []:
        if node.get("type") == "tab" and str(node.get("label", "")).startswith(LABEL_PREFIX):
            return node
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["ensure", "status", "remove"])
    parser.add_argument("--url", default="http://localhost:1880")
    parser.add_argument("--flow", help="chemin de diag_flow.json (pour ensure)")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    try:
        tab = find_tab(base)
        if args.command == "status":
            print("present" if tab else "absent")
            return 0
        if args.command == "remove":
            if tab:
                call("DELETE", f"{base}/flow/{tab['id']}")
                print("Onglet de diagnostic supprime.")
            else:
                print("Aucun onglet de diagnostic a supprimer.")
            return 0
        # ensure
        if tab:
            print("Onglet de diagnostic deja present.")
            return 0
        if not args.flow:
            print("--flow est requis pour ensure.", file=sys.stderr)
            return 1
        with open(args.flow, encoding="utf-8-sig") as stream:
            items = json.load(stream)
        source_tab = next(n for n in items if n.get("type") == "tab")
        nodes = [{k: v for k, v in n.items() if k != "z"} for n in items if n.get("type") != "tab"]
        result = call("POST", f"{base}/flow", {"label": source_tab["label"], "nodes": nodes})
        print(f"Onglet de diagnostic importe (id {result.get('id') if result else '?'}).")
        return 0
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        print(explain(exc, base), file=sys.stderr)
        return 1
    except (StopIteration, json.JSONDecodeError, KeyError) as exc:
        print(f"Fichier de flow invalide : {exc!r}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
