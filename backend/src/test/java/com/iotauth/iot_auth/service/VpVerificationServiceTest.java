package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import com.iotauth.iot_auth.util.CryptoUtils;
import com.iotauth.iot_auth.util.DataIntegrity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Le VC contenu dans la VP doit être identique au VC signé et stocké par l'Issuer. */
class VpVerificationServiceTest {

    private static final String STORED_VC =
            "{\"id\":\"vc-001\",\"issuer\":\"did:algo:admin\","
                    + "\"credentialSubject\":{\"id\":\"did:algo:dev\",\"permissions\":[\"read\"]},"
                    + "\"proof\":{\"proofValue\":\"SIG\"}}";

    private VpVerificationService service;

    @BeforeEach
    void setUp() {
        service = new VpVerificationService(new ObjectMapper());
        ReflectionTestUtils.setField(service, "expectedDomain", "iot-auth-test");
    }

    // --- Preuve Data Integrity de la VP (authentication, challenge, domain) ---

    private static final byte[] DEVICE_SEED = new byte[32];
    private static final String DEVICE_DID = "did:algo:custom:app:1032:dev";

    private String deviceKeyBase32() {
        return CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(DEVICE_SEED));
    }

    private String signedVp(String challenge, String domain, String holder, String verificationMethod) {
        Map<String, Object> vp = new LinkedHashMap<>();
        vp.put("@context", List.of("https://www.w3.org/ns/credentials/v2"));
        vp.put("type", List.of("VerifiablePresentation"));
        vp.put("holder", holder);
        vp.put("verifiableCredential", List.of(Map.of("id", "urn:uuid:1")));
        Map<String, Object> secured = DataIntegrity.addProof(
                vp, data -> CryptoUtils.signEd25519Bytes(DEVICE_SEED, data),
                verificationMethod, "authentication", "2026-10-13T01:00:00Z", challenge, domain);
        try {
            return new ObjectMapper().writeValueAsString(secured);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void validVpProof_isAccepted() {
        String vp = signedVp("nonce-1", "iot-auth-test", DEVICE_DID, DEVICE_DID + "#key-1");
        assertTrue(service.verifyPresentation(vp, "nonce-1", DEVICE_DID, deviceKeyBase32()));
    }

    @Test
    void vpProofWithWrongChallengeDomainHolderOrKey_isRejected() {
        String vp = signedVp("nonce-1", "iot-auth-test", DEVICE_DID, DEVICE_DID + "#key-1");
        assertFalse(service.verifyPresentation(vp, "nonce-2", DEVICE_DID, deviceKeyBase32()));
        assertFalse(service.verifyPresentation(vp, "nonce-1", "did:algo:custom:app:1032:other", deviceKeyBase32()));
        String otherDomain = signedVp("nonce-1", "autre-domaine", DEVICE_DID, DEVICE_DID + "#key-1");
        assertFalse(service.verifyPresentation(otherDomain, "nonce-1", DEVICE_DID, deviceKeyBase32()));
        String otherMethod = signedVp("nonce-1", "iot-auth-test", DEVICE_DID, DEVICE_DID + "#key-9");
        assertFalse(service.verifyPresentation(otherMethod, "nonce-1", DEVICE_DID, deviceKeyBase32()));
        byte[] otherSeed = new byte[32];
        otherSeed[0] = 1;
        String otherKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(otherSeed));
        assertFalse(service.verifyPresentation(vp, "nonce-1", DEVICE_DID, otherKey));
    }

    @Test
    void vpWithoutProofOrInVersion1Format_isRejected() {
        assertFalse(service.verifyPresentation(
                "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"holder\":\"" + DEVICE_DID + "\"}",
                "nonce-1", DEVICE_DID, deviceKeyBase32()));
        assertFalse(service.verifyPresentation("{}", "nonce-1", DEVICE_DID, deviceKeyBase32()));
    }

    private String vpWith(String vcJson) {
        return "{\"type\":\"VerifiablePresentation\",\"verifiableCredential\":[" + vcJson + "]}";
    }

    @Test
    void identicalVc_evenWithDifferentFieldOrder_shouldMatch() {
        String reordered =
                "{\"proof\":{\"proofValue\":\"SIG\"},\"credentialSubject\":{\"permissions\":[\"read\"],"
                        + "\"id\":\"did:algo:dev\"},\"issuer\":\"did:algo:admin\",\"id\":\"vc-001\"}";
        assertTrue(service.presentedCredentialMatches(vpWith(reordered), STORED_VC));
    }

    @Test
    void vcWithEscalatedPermissions_shouldNotMatch() {
        String tampered = STORED_VC.replace("\"read\"", "\"read\",\"admin\"");
        assertFalse(service.presentedCredentialMatches(vpWith(tampered), STORED_VC));
    }

    @Test
    void vpCarryingOnlyAnId_shouldNotMatch() {
        assertFalse(service.presentedCredentialMatches(vpWith("{\"id\":\"vc-001\"}"), STORED_VC));
    }

    @Test
    void vpCarryingVcAsString_shouldNotMatch() {
        assertFalse(service.presentedCredentialMatches(vpWith("\"vc-001\""), STORED_VC));
    }

    @Test
    void vpWithSeveralCredentials_shouldNotMatch() {
        assertFalse(service.presentedCredentialMatches(vpWith(STORED_VC + "," + STORED_VC), STORED_VC));
    }

    @Test
    void nullOrMalformedInputs_shouldNotMatch() {
        assertFalse(service.presentedCredentialMatches(null, STORED_VC));
        assertFalse(service.presentedCredentialMatches(vpWith(STORED_VC), null));
        assertFalse(service.presentedCredentialMatches("not-json", STORED_VC));
    }
}
