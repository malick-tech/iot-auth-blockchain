package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.util.CryptoUtils;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtServiceTest {

    @Test
    void generateJwtPop_shouldReturnNonNullResponse() {
        AdminKeyService adminKeyService = mock(AdminKeyService.class);
        when(adminKeyService.getAdminDid()).thenReturn("did:algo:ADMIN");
        when(adminKeyService.sign(org.mockito.ArgumentMatchers.anyString())).thenReturn("signature");

        JwtService service = new JwtService(adminKeyService);
        ReflectionTestUtils.setField(service, "jwtTtlSeconds", 3600L);

        byte[] privateKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String publicKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(privateKey));

        JwtPopResponse response = service.generateJwtPop("did:algo:ABC", publicKey);

        assertThat(response).isNotNull();
        assertThat(response.getJwt()).isNotBlank();
        assertThat(response.getDid()).isEqualTo("did:algo:ABC");
        assertThat(response.getExpiresIn()).isEqualTo(3600L);
    }
}
