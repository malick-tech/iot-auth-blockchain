package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.repository.VcRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Emission d'un VC W3C (VC 2.0 + Data Integrity eddsa-jcs-2022 + credentialStatus) avec une vraie cle d'Issuer. */
class VcServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private VcService service;
    private AdminKeyService adminKeyService;

    @BeforeEach
    void setUp() {
        VcRepository vcRepository = mock(VcRepository.class);
        DeviceRepository deviceRepository = mock(DeviceRepository.class);
        when(deviceRepository.findMaxStatusListIndex()).thenReturn(-1);
        when(vcRepository.save(org.mockito.ArgumentMatchers.any(VerifiableCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 1);
        }
        adminKeyService = new AdminKeyService(Base64.getEncoder().encodeToString(key), 1032L, "localnet");
        ReflectionTestUtils.invokeMethod(adminKeyService, "init");

        StatusListService statusListService = new StatusListService(deviceRepository, adminKeyService, objectMapper);
        ReflectionTestUtils.setField(statusListService, "publicBaseUrl", "http://backend.test");
        ReflectionTestUtils.setField(statusListService, "sizeBits", 131072);

        service = new VcService(vcRepository, adminKeyService, objectMapper, statusListService);
        ReflectionTestUtils.setField(service, "vcValidityDays", 365);
    }

    private Device device() {
        Device device = new Device();
        device.setSerialNumber("SN123");
        device.setDid("did:algo:custom:app:1032:abcd");
        device.setLogicalGroup("capteurs");
        return device;
    }

    @Test
    void issueCredential_producesW3cVcWithValidProofAndStatus() throws Exception {
        VerifiableCredential vc = service.issueCredential(device());

        assertThat(vc.getVcId()).startsWith("urn:uuid:");
        assertThat(vc.getIssuerDid()).isEqualTo(adminKeyService.getAdminDid());
        assertThat(vc.getPermissions()).contains("device:operate", "device:read", "group:capteurs:access");

        JsonNode json = objectMapper.readTree(vc.getRawCredential());
        assertThat(json.get("@context").get(0).asText()).isEqualTo("https://www.w3.org/ns/credentials/v2");
        assertThat(json.has("issuanceDate")).isFalse();
        assertThat(json.get("validFrom").asText()).endsWith("Z");
        assertThat(json.get("validUntil").asText()).endsWith("Z");
        assertThat(json.get("credentialSubject").get("permissions").size()).isEqualTo(3);
        assertThat(json.get("credentialStatus").size()).isEqualTo(2);
        assertThat(json.get("credentialStatus").get(0).get("type").asText()).isEqualTo("BitstringStatusListEntry");
        assertThat(json.get("credentialStatus").get(0).get("statusPurpose").asText()).isEqualTo("revocation");
        assertThat(json.get("credentialStatus").get(0).get("statusListIndex").asText()).isEqualTo("0");
        assertThat(json.get("credentialStatus").get(1).get("statusPurpose").asText()).isEqualTo("suspension");
        assertThat(json.get("proof").get("type").asText()).isEqualTo("DataIntegrityProof");
        assertThat(json.get("proof").get("cryptosuite").asText()).isEqualTo("eddsa-jcs-2022");
        assertThat(json.get("proof").get("proofValue").asText()).startsWith("z");

        assertThat(service.verifyIssuerSignature(vc.getRawCredential())).isTrue();
    }

    @Test
    void verifyIssuerSignature_rejectsTamperedCredential() {
        VerifiableCredential vc = service.issueCredential(device());
        String tampered = vc.getRawCredential().replace("device:read", "device:admin");
        assertThat(tampered).isNotEqualTo(vc.getRawCredential());
        assertThat(service.verifyIssuerSignature(tampered)).isFalse();
    }

    @Test
    void verifyIssuerSignature_rejectsGarbageAndLegacyFormat() {
        assertThat(service.verifyIssuerSignature("not json")).isFalse();
        assertThat(service.verifyIssuerSignature(
                "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiableCredential\"],"
                        + "\"proof\":{\"type\":\"Ed25519Signature2020\",\"proofValue\":\"x\"}}")).isFalse();
    }
}
