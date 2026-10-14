package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.util.BitstringStatusList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StatusListServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private DeviceRepository deviceRepository;
    private StatusListService service;

    @BeforeEach
    void setUp() {
        deviceRepository = mock(DeviceRepository.class);
        byte[] key = new byte[32];
        key[0] = 9;
        AdminKeyService admin = new AdminKeyService(Base64.getEncoder().encodeToString(key), 1032L, "localnet");
        ReflectionTestUtils.invokeMethod(admin, "init");
        service = new StatusListService(deviceRepository, admin, objectMapper);
        ReflectionTestUtils.setField(service, "publicBaseUrl", "http://backend.test");
        ReflectionTestUtils.setField(service, "sizeBits", 131072);
    }

    private static Device device(int index) {
        Device d = new Device();
        d.setStatusListIndex(index);
        return d;
    }

    @Test
    void ensureIndex_assignsNextFreeIndexOnce() {
        when(deviceRepository.findMaxStatusListIndex()).thenReturn(4);
        Device d = new Device();
        assertThat(service.ensureIndex(d)).isEqualTo(5);
        assertThat(service.ensureIndex(d)).isEqualTo(5);
    }

    @Test
    void ensureIndex_failsWhenListIsFull() {
        when(deviceRepository.findMaxStatusListIndex()).thenReturn(131071);
        assertThatThrownBy(() -> service.ensureIndex(new Device())).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void revocationList_flagsOnlyRevokedDevices() throws Exception {
        when(deviceRepository.findByStatus(DeviceStatus.REVOKED)).thenReturn(List.of(device(3), device(12)));
        JsonNode vc = objectMapper.readTree(service.buildStatusListCredential("revocation"));

        assertThat(vc.get("type").toString()).contains("BitstringStatusListCredential");
        assertThat(vc.get("credentialSubject").get("statusPurpose").asText()).isEqualTo("revocation");
        BitstringStatusList list = BitstringStatusList.decode(vc.get("credentialSubject").get("encodedList").asText());
        assertThat(list.get(3)).isTrue();
        assertThat(list.get(12)).isTrue();
        assertThat(list.get(4)).isFalse();
        assertThat(vc.get("proof").get("proofPurpose").asText()).isEqualTo("assertionMethod");
    }

    @Test
    void suspensionList_flagsOnlySuspendedDevices() throws Exception {
        when(deviceRepository.findByStatus(DeviceStatus.SUSPENDED)).thenReturn(List.of(device(7)));
        JsonNode vc = objectMapper.readTree(service.buildStatusListCredential("suspension"));
        BitstringStatusList list = BitstringStatusList.decode(vc.get("credentialSubject").get("encodedList").asText());
        assertThat(list.get(7)).isTrue();
        assertThat(list.get(3)).isFalse();
    }

    @Test
    void unknownPurposeIsRejected() {
        assertThatThrownBy(() -> service.buildStatusListCredential("other")).isInstanceOf(IllegalArgumentException.class);
    }
}
