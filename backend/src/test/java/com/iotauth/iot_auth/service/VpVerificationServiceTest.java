package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
