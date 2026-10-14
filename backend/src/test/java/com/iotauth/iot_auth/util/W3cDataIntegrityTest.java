package com.iotauth.iot_auth.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Les vecteurs ci-dessous sont produits par devices/w3c_di.py, lui-meme verifie contre l'implementation
 * de reference Digital Bazaar (voir devices/test_w3c_di.py). Si ce test passe, Java et Python produisent
 * exactement la meme preuve pour le meme document.
 */
class W3cDataIntegrityTest {

    private static final byte[] SEED = CryptoUtils.decodeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] PUBLIC_KEY = CryptoUtils.decodeHex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    private static final String VM = "did:algo:custom:app:1032:iss#key-1";
    private static final String EXPECTED_JCS =
            "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"credentialSubject\":{\"count\":42,\"flag\":true,"
                    + "\"id\":\"did:algo:custom:app:1032:abc\",\"nothing\":null,\"permissions\":[\"device:operate\",\"device:read\"],"
                    + "\"serialNumber\":\"SN-é-€-\\u0001-😀\"},\"issuer\":\"did:algo:custom:app:1032:iss\","
                    + "\"type\":[\"VerifiableCredential\"],\"validFrom\":\"2026-10-13T01:00:00Z\"}";
    private static final String EXPECTED_PROOF_VALUE =
            "z4MY4dDCFmYbGwGXDympcBrpHww6kfr2rbMxbVqw3jZrFcTFfFeeU116n54rSGmEkUiqMM2jVf8JrjWLzUjqEvBCA";

    private static Map<String, Object> document() {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("id", "did:algo:custom:app:1032:abc");
        subject.put("serialNumber", "SN-é-€-\u0001-😀");
        subject.put("count", 42L);
        subject.put("flag", true);
        subject.put("nothing", null);
        subject.put("permissions", List.of("device:operate", "device:read"));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", List.of("https://www.w3.org/ns/credentials/v2"));
        doc.put("type", List.of("VerifiableCredential"));
        doc.put("issuer", "did:algo:custom:app:1032:iss");
        doc.put("credentialSubject", subject);
        doc.put("validFrom", "2026-10-13T01:00:00Z");
        return doc;
    }

    private static final DataIntegrity.Signer SIGNER = data -> CryptoUtils.signEd25519Bytes(SEED, data);
    private static final DataIntegrity.Verifier VERIFIER = (data, sig) -> CryptoUtils.verifyEd25519Bytes(PUBLIC_KEY, data, sig);

    @Test
    void jcs_matchesPythonAndReferenceOutput() {
        assertEquals(EXPECTED_JCS, new String(Jcs.canonicalize(document()), StandardCharsets.UTF_8));
    }

    @Test
    void jcs_sortsKeysByUtf16CodeUnits() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("דּ", 1L);       // U+FB33
        m.put("😀", 2L); // U+1F600 (substituts D83D DE00) : trie avant U+FB33 en UTF-16
        assertEquals("{\"😀\":2,\"דּ\":1}", new String(Jcs.canonicalize(m), StandardCharsets.UTF_8));
    }

    @Test
    void jcs_rejectsNonIntegerNumbers() {
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(Map.of("x", 1.5)));
    }

    @Test
    void proof_matchesPythonVector() {
        Map<String, Object> secured = DataIntegrity.addProof(document(), SIGNER, VM, "assertionMethod", "2026-10-13T01:00:00Z", null, null);
        @SuppressWarnings("unchecked")
        Map<String, Object> proof = (Map<String, Object>) secured.get("proof");
        assertEquals(EXPECTED_PROOF_VALUE, proof.get("proofValue"));
        assertEquals("DataIntegrityProof", proof.get("type"));
        assertEquals("eddsa-jcs-2022", proof.get("cryptosuite"));
    }

    @Test
    void verify_acceptsValidProofAndRejectsTamperingAndMismatches() throws Exception {
        Map<String, Object> secured = DataIntegrity.addProof(document(), SIGNER, VM, "assertionMethod", "2026-10-13T01:00:00Z", "ch-1", "dom-1");
        DataIntegrity.verify(secured, VERIFIER, "assertionMethod", VM, "ch-1", "dom-1");

        assertThrows(DataIntegrity.ProofException.class, () -> DataIntegrity.verify(secured, VERIFIER, "authentication", VM, "ch-1", "dom-1"));
        assertThrows(DataIntegrity.ProofException.class, () -> DataIntegrity.verify(secured, VERIFIER, "assertionMethod", VM + "x", "ch-1", "dom-1"));
        assertThrows(DataIntegrity.ProofException.class, () -> DataIntegrity.verify(secured, VERIFIER, "assertionMethod", VM, "ch-2", "dom-1"));
        assertThrows(DataIntegrity.ProofException.class, () -> DataIntegrity.verify(secured, VERIFIER, "assertionMethod", VM, "ch-1", "dom-2"));

        @SuppressWarnings("unchecked")
        Map<String, Object> subject = new LinkedHashMap<>((Map<String, Object>) secured.get("credentialSubject"));
        subject.put("count", 43L);
        Map<String, Object> tampered = new LinkedHashMap<>(secured);
        tampered.put("credentialSubject", subject);
        assertThrows(DataIntegrity.ProofException.class, () -> DataIntegrity.verify(tampered, VERIFIER, "assertionMethod", VM, "ch-1", "dom-1"));

        Map<String, Object> extraContext = new LinkedHashMap<>(secured);
        extraContext.put("@context", List.of("https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/undefined-terms/v2"));
        assertThrows(DataIntegrity.ProofException.class, () -> DataIntegrity.verify(extraContext, VERIFIER, "assertionMethod", VM, "ch-1", "dom-1"));
    }

    @Test
    void multikey_roundTripAndKnownPrefix() {
        String mk = Multibase.multikeyEd25519(PUBLIC_KEY);
        assertTrue(mk.startsWith("z6Mk"));
        assertArrayEquals(PUBLIC_KEY, Multibase.publicKeyFromMultikey(mk));
        assertEquals("z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd", mk);
    }

    @Test
    void base58_preservesLeadingZeros() {
        byte[] data = {0, 0, 1, 2, 3};
        assertArrayEquals(data, Multibase.decodeBase58btc(Multibase.encodeBase58btc(data)));
    }

    @Test
    void statusList_bitOrderAndEncodingMatchPython() {
        BitstringStatusList list = new BitstringStatusList(131072);
        for (int i : new int[]{0, 7, 9, 131071}) {
            list.set(i, true);
        }
        assertEquals("uH4sIAAAAAAAA_-3BMQEAAAgDINfMajY3xh7gdgAAAAAAAAAAAAAAAAAAAICuPBc7K4AAQAAA", list.encode());
        BitstringStatusList decoded = BitstringStatusList.decode(list.encode());
        assertTrue(decoded.get(0));
        assertFalse(decoded.get(1));
        assertTrue(decoded.get(7));
        assertTrue(decoded.get(9));
        assertTrue(decoded.get(131071));
        assertThrows(IllegalArgumentException.class, () -> new BitstringStatusList(1024));
    }
}
