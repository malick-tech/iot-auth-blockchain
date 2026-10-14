"""Tests de devices/w3c_di.py : cas de base + comparaison avec des implementations independantes.

Les comparaisons croisees (module `jcs`, bibliotheque `base58`, et verificateur
Node @digitalbazaar/*) sont executees si ces outils sont disponibles ; sinon
elles sont ignorees (skip) et seuls les tests unitaires s'executent.
"""
import json
import os
import random
import shutil
import string
import subprocess
import unittest

import nacl.signing

import w3c_di as w

SEED = bytes([7]) * 32
KEY = nacl.signing.SigningKey(SEED)
PK = bytes(KEY.verify_key)
ISSUER = w.did_key_ed25519(PK)
VM = w.did_key_verification_method(PK)

DOC = {
    "@context": [w.VC_CONTEXT_V2],
    "type": ["VerifiableCredential"],
    "issuer": ISSUER,
    "validFrom": "2026-10-13T00:00:00Z",
    "credentialSubject": {"id": "did:example:sub", "permissions": ["a", "b"], "n": 3, "ok": True},
}


class JcsTests(unittest.TestCase):
    def test_sorted_and_compact(self):
        self.assertEqual(w.jcs({"b": 1, "a": [True, None, "x"]}), b'{"a":[true,null,"x"],"b":1}')

    def test_utf16_ordering(self):
        # U+10000 (paire de substitution D800 DC00) se range AVANT U+E000 en UTF-16.
        self.assertEqual(w.jcs({"": 1, "\U00010000": 2}), '{"\U00010000":2,"":1}'.encode("utf-8"))

    def test_rejects_float(self):
        with self.assertRaises(ValueError):
            w.jcs({"x": 1.5})

    def test_differential_against_jcs_module(self):
        try:
            import jcs as ref
        except ImportError:
            self.skipTest("module jcs absent")
        rnd = random.Random(1)
        alphabet = string.ascii_letters + string.digits + ' "\\/\n\té€\U0001f600 \x7f\x01'

        def rstr():
            return "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 8)))

        def rval(d=0):
            t = rnd.randint(0, 6 if d < 3 else 3)
            if t == 0:
                return None
            if t == 1:
                return rnd.choice([True, False])
            if t == 2:
                return rnd.randint(-10**9, 10**9)
            if t == 3:
                return rstr()
            if t in (4, 5):
                return [rval(d + 1) for _ in range(rnd.randint(0, 4))]
            return {rstr(): rval(d + 1) for _ in range(rnd.randint(0, 4))}

        for _ in range(2000):
            v = rval()
            self.assertEqual(w.jcs(v), ref.canonicalize(v))


class MultibaseTests(unittest.TestCase):
    def test_roundtrip_and_leading_zero(self):
        for data in [b"", b"\x00", b"\x00\x00ab", os.urandom(32), bytes(range(40))]:
            self.assertEqual(w.b58decode(w.b58encode(data)), data)

    def test_against_base58_module(self):
        try:
            import base58
        except ImportError:
            self.skipTest("module base58 absent")
        for _ in range(500):
            data = os.urandom(random.randint(0, 70))
            self.assertEqual(w.b58encode(data), base58.b58encode(data).decode())

    def test_multikey_prefix(self):
        mk = w.multikey_ed25519(PK)
        self.assertTrue(mk.startswith("z6Mk"))
        self.assertEqual(w.public_key_from_multikey(mk), PK)


class ProofTests(unittest.TestCase):
    def secured(self, **kw):
        return w.add_proof(DOC, KEY, VM, "assertionMethod", "2026-10-13T00:00:00Z", **kw)

    def test_roundtrip(self):
        w.verify_proof(self.secured(), PK, "assertionMethod", expected_verification_method=VM)

    def test_deterministic(self):
        self.assertEqual(self.secured()["proof"]["proofValue"], self.secured()["proof"]["proofValue"])

    def test_tamper_document(self):
        d = self.secured()
        d["credentialSubject"]["permissions"].append("admin")
        with self.assertRaises(w.ProofError):
            w.verify_proof(d, PK, "assertionMethod")

    def test_tamper_proof_option(self):
        d = self.secured()
        d["proof"]["created"] = "2026-10-14T00:00:00Z"
        with self.assertRaises(w.ProofError):
            w.verify_proof(d, PK, "assertionMethod")

    def test_wrong_purpose_challenge_domain(self):
        d = w.add_proof(DOC, KEY, VM, "authentication", "2026-10-13T00:00:00Z", challenge="c1", domain="d1")
        w.verify_proof(d, PK, "authentication", expected_challenge="c1", expected_domain="d1")
        for kw in ({"expected_challenge": "c2"}, {"expected_domain": "d2"}):
            with self.assertRaises(w.ProofError):
                w.verify_proof(d, PK, "authentication", **kw)
        with self.assertRaises(w.ProofError):
            w.verify_proof(d, PK, "assertionMethod")

    def test_wrong_key(self):
        other = bytes(nacl.signing.SigningKey(bytes([9]) * 32).verify_key)
        with self.assertRaises(w.ProofError):
            w.verify_proof(self.secured(), other, "assertionMethod")

    def test_swapping_context_is_detected(self):
        d = self.secured()
        d["@context"] = [w.VC_CONTEXT_V2, w.UNDEFINED_TERMS_CONTEXT_V2]
        with self.assertRaises(w.ProofError):
            w.verify_proof(d, PK, "assertionMethod")



class CrossLanguageVectorTests(unittest.TestCase):
    """Meme vecteur que backend/src/test/.../W3cDataIntegrityTest.java : Java et Python doivent produire la meme preuve."""

    def test_proof_value_matches_java_test_vector(self):
        sk = nacl.signing.SigningKey(bytes(range(32)))
        subject = {"id": "did:algo:custom:app:1032:abc", "serialNumber": "SN-\u00e9-\u20ac-\u0001-\U0001F600",
                   "count": 42, "flag": True, "nothing": None, "permissions": ["device:operate", "device:read"]}
        doc = {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"],
               "issuer": "did:algo:custom:app:1032:iss", "credentialSubject": subject, "validFrom": "2026-10-13T01:00:00Z"}
        secured = w.add_proof(doc, sk, "did:algo:custom:app:1032:iss#key-1", "assertionMethod", "2026-10-13T01:00:00Z")
        self.assertEqual(secured["proof"]["proofValue"],
                         "z4MY4dDCFmYbGwGXDympcBrpHww6kfr2rbMxbVqw3jZrFcTFfFeeU116n54rSGmEkUiqMM2jVf8JrjWLzUjqEvBCA")
        self.assertEqual(w.multikey_ed25519(bytes(sk.verify_key)), "z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd")


NODE_DIR = os.environ.get("W3C_NODE_TOOLS", "")


@unittest.skipUnless(NODE_DIR and shutil.which("node"), "W3C_NODE_TOOLS (bibliotheques @digitalbazaar) non defini")
class InteropTests(unittest.TestCase):
    """Verification croisee avec l'implementation de reference Digital Bazaar."""

    def run_node(self, script, payload):
        res = subprocess.run(
            ["node", os.path.join(NODE_DIR, script)], input=json.dumps(payload), text=True,
            capture_output=True, cwd=NODE_DIR, timeout=60,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def test_node_signs_python_verifies(self):
        out = self.run_node("interop_sign.mjs", {"seedHex": SEED.hex(), "document": DOC,
                                                 "purpose": "assertionMethod", "created": "2026-10-13T00:00:00Z"})
        w.verify_proof(out, PK, "assertionMethod", expected_verification_method=VM)
        # Ed25519 est deterministe : meme signature octet pour octet.
        self.assertEqual(out["proof"]["proofValue"], w.add_proof(DOC, KEY, VM, "assertionMethod",
                                                                  "2026-10-13T00:00:00Z")["proof"]["proofValue"])

    def test_python_signs_node_verifies(self):
        d = w.add_proof(DOC, KEY, VM, "assertionMethod", "2026-10-13T00:00:00Z")
        out = self.run_node("interop_verify.mjs", {"document": d, "purpose": "assertionMethod"})
        self.assertTrue(out["verified"], out)

    def test_python_presentation_node_verifies(self):
        vc = w.add_proof(DOC, KEY, VM, "assertionMethod", "2026-10-13T00:00:00Z")
        holder_key = nacl.signing.SigningKey(bytes([5]) * 32)
        holder_pk = bytes(holder_key.verify_key)
        holder = w.did_key_ed25519(holder_pk)  # did:key pour l'interop du verificateur de reference
        vp = json.loads(w.secure_presentation(holder, vc, holder_key, "nonce-123", "did:web:verifier.example",
                                              "2026-10-13T00:00:01Z"))
        vp["proof"]["verificationMethod"] = w.did_key_verification_method(holder_pk)
        # re-signe avec le bon verificationMethod
        unsigned = {k: v for k, v in vp.items() if k != "proof"}
        vp = w.add_proof(unsigned, holder_key, w.did_key_verification_method(holder_pk), "authentication",
                         "2026-10-13T00:00:01Z", challenge="nonce-123", domain="did:web:verifier.example")
        out = self.run_node("interop_verify.mjs", {"document": vp, "purpose": "authentication",
                                                   "challenge": "nonce-123", "domain": "did:web:verifier.example"})
        self.assertTrue(out["verified"], out)
        # tentative avec un mauvais challenge : refus par le verificateur de reference
        bad = self.run_node("interop_verify.mjs", {"document": vp, "purpose": "authentication",
                                                   "challenge": "autre", "domain": "did:web:verifier.example"})
        self.assertFalse(bad["verified"])


if __name__ == "__main__":
    unittest.main()
