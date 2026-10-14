"""
Primitives W3C utilisees par le simulateur d'appareil et par les scripts de test.

Contenu (dependances : PyNaCl uniquement, deja requise par le simulateur) :
  - canonicalisation JSON JCS (RFC 8785), sur le sous-ensemble JSON utilise ici
    (chaines, entiers surs, booleens, null, listes, objets) ;
  - encodage multibase base58btc (prefixe "z") et Multikey Ed25519 (0xed01) ;
  - did:key pour Ed25519 ;
  - suite de preuve Data Integrity "eddsa-jcs-2022" (W3C Data Integrity EdDSA
    Cryptosuites v1.0, section 3.3) : creation et verification ;
  - construction d'une Verifiable Presentation (VC Data Model 2.0) avec preuve
    de purpose "authentication", challenge et domain.

Ce module ne fait aucun appel reseau. Il est valide par differents tests contre
des implementations independantes (voir devices/test_w3c_di.py).
"""

import hashlib
import json
from typing import Any, Dict, List, Optional

import nacl.signing

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
UNDEFINED_TERMS_CONTEXT_V2 = "https://www.w3.org/ns/credentials/undefined-terms/v2"
CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
_MAX_SAFE_INTEGER = 2**53 - 1


# ---------------------------------------------------------------------------
# JCS (RFC 8785)
# ---------------------------------------------------------------------------


def _utf16_key(key: str) -> bytes:
    # RFC 8785 §3.2.3 : tri des noms de proprietes par unites de code UTF-16.
    return key.encode("utf-16-be", "surrogatepass")


def _jcs_serialize(value: Any, out: List[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        # json.dumps(ensure_ascii=False) echappe exactement ce que demande
        # RFC 8785 §3.2.2.2 (", \\, \b \t \n \f \r, autres controles en \u00xx
        # minuscules) et laisse le reste tel quel.
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError("entier hors de l'intervalle sur de JSON (2^53-1)")
        out.append(str(value))
    elif isinstance(value, float):
        raise ValueError("nombres non entiers non pris en charge (JCS) : utiliser des chaines")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _jcs_serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value.keys(), key=_utf16_key)):
            if not isinstance(key, str):
                raise ValueError("les cles d'objet doivent etre des chaines")
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _jcs_serialize(value[key], out)
        out.append("}")
    else:
        raise ValueError(f"type non serialisable en JCS : {type(value).__name__}")


def jcs(value: Any) -> bytes:
    """Forme canonique JCS de `value`, encodee en UTF-8."""
    out: List[str] = []
    _jcs_serialize(value, out)
    return "".join(out).encode("utf-8")


# ---------------------------------------------------------------------------
# Multibase / Multikey / did:key
# ---------------------------------------------------------------------------


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        if ch not in _B58_INDEX:
            raise ValueError("caractere base58 invalide")
        n = n * 58 + _B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading_ones = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_ones + body


def multibase_b58btc(data: bytes) -> str:
    return "z" + b58encode(data)


def multibase_b58btc_decode(text: str) -> bytes:
    if not text.startswith("z"):
        raise ValueError("multibase base58btc attendu (prefixe 'z')")
    return b58decode(text[1:])


def multikey_ed25519(public_key: bytes) -> str:
    """publicKeyMultibase d'une cle Ed25519 : 'z' + base58btc(0xed01 || cle)."""
    if len(public_key) != 32:
        raise ValueError("cle publique Ed25519 de 32 octets attendue")
    return multibase_b58btc(b"\xed\x01" + public_key)


def public_key_from_multikey(multibase: str) -> bytes:
    raw = multibase_b58btc_decode(multibase)
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        raise ValueError("Multikey Ed25519 invalide (prefixe 0xed01 attendu)")
    return raw[2:]


def did_key_ed25519(public_key: bytes) -> str:
    return "did:key:" + multikey_ed25519(public_key)


def did_key_verification_method(public_key: bytes) -> str:
    mk = multikey_ed25519(public_key)
    return f"did:key:{mk}#{mk}"


# ---------------------------------------------------------------------------
# Data Integrity : eddsa-jcs-2022
# ---------------------------------------------------------------------------


def _hash_data(proof_options: Dict[str, Any], unsecured_document: Dict[str, Any]) -> bytes:
    # §3.3.4 : proofConfigHash || transformedDocumentHash, SHA-256 chacun.
    return hashlib.sha256(jcs(proof_options)).digest() + hashlib.sha256(jcs(unsecured_document)).digest()


def add_proof(
    unsecured_document: Dict[str, Any],
    signing_key: nacl.signing.SigningKey,
    verification_method: str,
    proof_purpose: str,
    created: str,
    challenge: Optional[str] = None,
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    """Retourne une copie du document avec un champ `proof` eddsa-jcs-2022.

    `created` doit etre un dateTimeStamp XML Schema avec fuseau (ex. "2026-10-13T01:00:00Z").
    """
    if "proof" in unsecured_document:
        raise ValueError("le document contient deja une preuve")
    options: Dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "created": created,
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }
    if challenge is not None:
        options["challenge"] = challenge
    if domain is not None:
        options["domain"] = domain
    # §3.3.1 etape 2 : le @context du document est copie dans la preuve ; la
    # preuve integree le conserve (comportement des implementations de reference).
    if "@context" in unsecured_document:
        options["@context"] = unsecured_document["@context"]
    signature = signing_key.sign(_hash_data(options, unsecured_document)).signature
    proof = dict(options)
    proof["proofValue"] = multibase_b58btc(signature)
    secured = dict(unsecured_document)
    secured["proof"] = proof
    return secured


class ProofError(Exception):
    pass


def verify_proof(
    secured_document: Dict[str, Any],
    public_key: bytes,
    expected_purpose: str,
    expected_verification_method: Optional[str] = None,
    expected_challenge: Optional[str] = None,
    expected_domain: Optional[str] = None,
) -> None:
    """Leve ProofError si la preuve n'est pas valide ou ne correspond pas aux attentes."""
    proof = secured_document.get("proof")
    if not isinstance(proof, dict):
        raise ProofError("proof absente ou multiple")
    if proof.get("type") != PROOF_TYPE or proof.get("cryptosuite") != CRYPTOSUITE:
        raise ProofError("suite de preuve non prise en charge")
    if proof.get("proofPurpose") != expected_purpose:
        raise ProofError("proofPurpose inattendu")
    if expected_verification_method is not None and proof.get("verificationMethod") != expected_verification_method:
        raise ProofError("verificationMethod inattendu")
    if expected_challenge is not None and proof.get("challenge") != expected_challenge:
        raise ProofError("challenge inattendu")
    if expected_domain is not None and proof.get("domain") != expected_domain:
        raise ProofError("domain inattendu")
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str):
        raise ProofError("proofValue absente")
    try:
        signature = multibase_b58btc_decode(proof_value)
    except ValueError as exc:
        raise ProofError(str(exc)) from exc
    if len(signature) != 64:
        raise ProofError("signature de 64 octets attendue")

    options = {k: v for k, v in proof.items() if k != "proofValue"}
    unsecured = {k: v for k, v in secured_document.items() if k != "proof"}
    if "@context" in options:
        # §3.3.2 etape 4 : le @context du document doit commencer par celui des options.
        doc_ctx = unsecured.get("@context")
        doc_ctx = doc_ctx if isinstance(doc_ctx, list) else [doc_ctx]
        opt_ctx = options["@context"] if isinstance(options["@context"], list) else [options["@context"]]
        # La spec exige seulement que le contexte du document COMMENCE par celui de la
        # preuve. Profil du projet, plus strict : egalite exacte, afin qu'aucun contexte
        # (donc aucun terme) ne puisse etre ajoute apres signature.
        if doc_ctx != opt_ctx:
            raise ProofError("@context du document different de celui de la preuve")
        unsecured["@context"] = options["@context"]

    try:
        nacl.signing.VerifyKey(public_key).verify(_hash_data(options, unsecured), signature)
    except Exception as exc:  # nacl.exceptions.BadSignatureError
        raise ProofError("signature invalide") from exc


# ---------------------------------------------------------------------------
# Verifiable Presentation (VC Data Model 2.0)
# ---------------------------------------------------------------------------


def build_presentation(holder_did: str, credential: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "@context": [VC_CONTEXT_V2],
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": [credential],
    }


def secure_presentation(
    holder_did: str,
    credential: Dict[str, Any],
    signing_key: nacl.signing.SigningKey,
    challenge: str,
    domain: str,
    created: str,
) -> str:
    """VP signee (authentication), serialisee en chaine JSON compacte transmise telle quelle."""
    vp = build_presentation(holder_did, credential)
    secured = add_proof(
        vp,
        signing_key,
        verification_method=f"{holder_did}#key-1",
        proof_purpose="authentication",
        created=created,
        challenge=challenge,
        domain=domain,
    )
    return json.dumps(secured, separators=(",", ":"), ensure_ascii=False)
