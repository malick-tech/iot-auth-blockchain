"""Test on-chain de l'irreversibilite de la revocation (correctif I-3).

A executer sur Algorand LocalNet (algokit localnet start). Deploie une instance
NEUVE du contrat (approval.teal regenere par `python contract.py`), puis verifie
que le CONTRAT lui-meme, et pas seulement la politique du backend, refuse :

  1. de repasser un DID revoque (statut 02) a 01 ;
  2. de republier (ecraser) un DID revoque ;
  3. un statut autre que 01/02 ;
  4. la mise a jour et la suppression de l'application, meme par l'admin ;
  5. toute ecriture par un compte non admin.

Et que les operations legitimes restent possibles (publication, revocation,
re-soumission idempotente de la revocation par le service de reprise).

Variables : ALGORAND_ALGOD_ADDRESS, ALGORAND_ALGOD_TOKEN, ALGORAND_DEPLOYER_MNEMONIC.
Code de sortie 0 si tous les controles passent, 1 sinon.
"""
import base64
import os
import sys

from algosdk import account, mnemonic, transaction
from algosdk.error import AlgodHTTPError
from algosdk.v2client import algod

ALGOD_ADDRESS = os.getenv("ALGORAND_ALGOD_ADDRESS", "http://localhost:4001")
ALGOD_TOKEN = os.getenv("ALGORAND_ALGOD_TOKEN", "a" * 64)
DEPLOYER_MNEMONIC = os.getenv("ALGORAND_DEPLOYER_MNEMONIC", "")

client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not ok else ""))


def compile_teal(path: str) -> bytes:
    with open(path, encoding="utf-8") as f:
        return base64.b64decode(client.compile(f.read())["result"])


def send(txn, key) -> None:
    tx_id = client.send_transaction(txn.sign(key))
    transaction.wait_for_confirmation(client, tx_id, 4)


def must_succeed(name, txn, key):
    try:
        send(txn, key)
        check(name, True)
    except Exception as exc:  # noqa: BLE001
        check(name, False, str(exc)[:160])


def must_be_rejected(name, txn, key):
    try:
        send(txn, key)
        check(name, False, "la transaction a ete ACCEPTEE alors qu'elle devait etre refusee")
    except AlgodHTTPError as exc:
        check(name, "rejected" in str(exc).lower() or "logic eval" in str(exc).lower(), str(exc)[:160])
    except Exception as exc:  # noqa: BLE001
        check(name, False, f"erreur inattendue : {str(exc)[:160]}")


def main() -> int:
    if not DEPLOYER_MNEMONIC:
        print("Definir ALGORAND_DEPLOYER_MNEMONIC (compte LocalNet finance).")
        return 2
    admin_key = mnemonic.to_private_key(DEPLOYER_MNEMONIC)
    admin = account.address_from_private_key(admin_key)
    approval = compile_teal("approval.teal")
    clear = compile_teal("clear.teal")

    sp = client.suggested_params()
    create = transaction.ApplicationCreateTxn(
        admin, sp, transaction.OnComplete.NoOpOC, approval, clear,
        transaction.StateSchema(0, 1), transaction.StateSchema(0, 0))
    tx_id = client.send_transaction(create.sign(admin_key))
    app_id = transaction.wait_for_confirmation(client, tx_id, 4)["application-index"]
    app_addr = transaction.logic.get_application_address(app_id)
    send(transaction.PaymentTxn(admin, client.suggested_params(), app_addr, 10_000_000), admin_key)
    print(f"Instance neuve du contrat : App ID {app_id}\n")

    def call(args, subject, extra_boxes=(), sender=admin, key=admin_key):
        boxes = [(0, subject)] + [(0, b) for b in extra_boxes]
        return transaction.ApplicationNoOpTxn(sender, client.suggested_params(), app_id, args, boxes=boxes)

    def ids(n: int) -> tuple[bytes, bytes]:
        pub = bytes([n]) * 32
        return pub, (n).to_bytes(8, "big")

    pub1, dk1 = ids(1)
    doc = b'{"id":"did:test"}'
    ready, deleted, invalid = b"\x01", b"\x02", b"\x03"

    # --- operations legitimes
    must_succeed("publication d'un DID", call([b"PUBLISH_DID", pub1, dk1, doc], pub1, [dk1]), admin_key)
    must_succeed("revocation (01 -> 02)", call([b"UPDATE_STATUS", pub1, deleted], pub1), admin_key)
    must_succeed("re-soumission idempotente de la revocation (02 -> 02)",
                 call([b"UPDATE_STATUS", pub1, deleted], pub1), admin_key)

    # --- irreversibilite par le contrat
    must_be_rejected("retour arriere 02 -> 01 refuse", call([b"UPDATE_STATUS", pub1, ready], pub1), admin_key)
    must_be_rejected("republication d'un DID revoque refusee",
                     call([b"PUBLISH_DID", pub1, dk1, doc], pub1, [dk1]), admin_key)

    # --- valeurs de statut
    pub2, dk2 = ids(2)
    must_succeed("publication d'un second DID", call([b"PUBLISH_DID", pub2, dk2, doc], pub2, [dk2]), admin_key)
    must_be_rejected("statut arbitraire 03 refuse", call([b"UPDATE_STATUS", pub2, invalid], pub2), admin_key)

    # --- contrat immuable
    must_be_rejected("UpdateApplication refuse (meme admin)", transaction.ApplicationUpdateTxn(
        admin, client.suggested_params(), app_id, approval, clear), admin_key)
    must_be_rejected("DeleteApplication refuse (meme admin)", transaction.ApplicationDeleteTxn(
        admin, client.suggested_params(), app_id), admin_key)

    # --- compte non admin
    other_key, other = account.generate_account()
    send(transaction.PaymentTxn(admin, client.suggested_params(), other, 1_000_000), admin_key)
    pub3, dk3 = ids(3)
    must_be_rejected("publication par un non-admin refusee",
                     call([b"PUBLISH_DID", pub3, dk3, doc], pub3, [dk3], sender=other), other_key)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} controles passes")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
