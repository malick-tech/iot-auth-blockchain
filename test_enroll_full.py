"""
Reproduit exactement le flux EnrollmentService.handleChallengeResponse()
et capture l'erreur Algorand complète depuis Python.
"""
import sys
sys.path.insert(0, "devices")
from device_simulator import load_or_create_identity, sign_b64url, signing_key_from_state
import requests

BASE = "http://localhost:8083"

state = load_or_create_identity("IOT-TEMP-001", 1014)
sk    = signing_key_from_state(state)
serial = state["serialNumber"]
did    = state["did"]

print(f"DID:       {did}")
print(f"PublicKey: {state['publicKeyBase32']}")

# Step 1 : first-contact
r1 = requests.post(f"{BASE}/api/enrollment/first-contact", json={
    "serialNumber": serial,
    "did": did,
    "publicKey": state["publicKeyBase32"],
    "signature": sign_b64url(sk, serial + did),
}, timeout=10)
print(f"\nfirst-contact: {r1.status_code}")
if r1.status_code != 200:
    print("Erreur:", r1.text)
    sys.exit(1)

nonce = r1.json()["nonce"]
print(f"Nonce: {nonce}")

# Step 2 : challenge-response  (déclenche la publication Algorand)
r2 = requests.post(f"{BASE}/api/enrollment/challenge-response", json={
    "did": did,
    "signedNonce": sign_b64url(sk, nonce),
}, timeout=45)
print(f"\nchallenge-response: {r2.status_code}")
print(r2.text[:2000])
