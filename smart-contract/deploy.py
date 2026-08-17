import base64
import os

from algosdk import account, mnemonic, transaction
from algosdk.v2client import algod

ALGOD_ADDRESS = os.getenv("ALGORAND_ALGOD_ADDRESS", "http://localhost:4001")
ALGOD_TOKEN = os.getenv("ALGORAND_ALGOD_TOKEN", "a" * 64)
DEPLOYER_MNEMONIC = os.getenv("ALGORAND_DEPLOYER_MNEMONIC", "")


def compile_program(client, source_code):
    compile_response = client.compile(source_code)
    return compile_response["result"], compile_response["hash"]


def deploy():
    if not DEPLOYER_MNEMONIC:
        raise RuntimeError("Set ALGORAND_DEPLOYER_MNEMONIC before deploying the contract.")

    algod_client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)

    private_key = mnemonic.to_private_key(DEPLOYER_MNEMONIC)
    sender = account.address_from_private_key(private_key)
    print("Compte deployeur (Admin) :", sender)

    with open("approval.teal") as f:
        approval_source = f.read()
    with open("clear.teal") as f:
        clear_source = f.read()

    approval_compiled, _ = compile_program(algod_client, approval_source)
    clear_compiled, _ = compile_program(algod_client, clear_source)

    approval_bytes = base64.b64decode(approval_compiled)
    clear_bytes = base64.b64decode(clear_compiled)

    global_schema = transaction.StateSchema(num_uints=0, num_byte_slices=1)
    local_schema = transaction.StateSchema(num_uints=0, num_byte_slices=0)

    params = algod_client.suggested_params()

    txn = transaction.ApplicationCreateTxn(
        sender=sender,
        sp=params,
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval_bytes,
        clear_program=clear_bytes,
        global_schema=global_schema,
        local_schema=local_schema,
    )

    signed_txn = txn.sign(private_key)
    tx_id = algod_client.send_transaction(signed_txn)
    print("Transaction envoyee :", tx_id)

    result = transaction.wait_for_confirmation(algod_client, tx_id, 4)
    app_id = result["application-index"]
    app_address = transaction.logic.get_application_address(app_id)

    print("=" * 50)
    print("App ID      :", app_id)
    print("App Address :", app_address)
    print("=" * 50)

    fund_params = algod_client.suggested_params()
    fund_txn = transaction.PaymentTxn(
        sender=sender,
        sp=fund_params,
        receiver=app_address,
        amt=10_000_000,
    )
    signed_fund_txn = fund_txn.sign(private_key)
    fund_tx_id = algod_client.send_transaction(signed_fund_txn)
    transaction.wait_for_confirmation(algod_client, fund_tx_id, 4)
    print("Compte de l'application finance (10 ALGOS)")


if __name__ == "__main__":
    deploy()
