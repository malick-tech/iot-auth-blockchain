package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.repository.VcRepository;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VcServiceTest {

    @Test
    void issueCredential_shouldReturnValidVerifiableCredential() {
        VcRepository vcRepository = mock(VcRepository.class);
        AdminKeyService adminKeyService = mock(AdminKeyService.class);
        VcService service = new VcService(vcRepository, adminKeyService);
        ReflectionTestUtils.setField(service, "vcValidityDays", 365);

        when(adminKeyService.getAdminDid()).thenReturn("did:algo:ADMIN");
        when(adminKeyService.sign(org.mockito.ArgumentMatchers.anyString())).thenReturn("signature");
        when(vcRepository.save(org.mockito.ArgumentMatchers.any(VerifiableCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        Device device = new Device();
        device.setSerialNumber("SN123");
        device.setDid("did:algo:DEVICE");
        device.setLogicalGroup("capteurs");

        VerifiableCredential vc = service.issueCredential(device);

        assertThat(vc).isNotNull();
        assertThat(vc.getVcId()).startsWith("vc-");
        assertThat(vc.getIssuerDid()).isEqualTo("did:algo:ADMIN");
        assertThat(vc.getSubjectDid()).isEqualTo("did:algo:DEVICE");
        assertThat(vc.getPermissions()).contains("device:operate", "device:read", "group:capteurs:access");
        assertThat(vc.getRawCredential()).contains("\"proofValue\":\"signature\"");
    }
}
