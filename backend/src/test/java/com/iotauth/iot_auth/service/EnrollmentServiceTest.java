package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.dto.request.ChallengeResponseRequest;
import com.iotauth.iot_auth.dto.request.FirstContactRequest;
import com.iotauth.iot_auth.dto.response.ChallengeResponse;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.exception.NonceExpiredException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.util.CryptoUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EnrollmentServiceTest {

    @Mock
    private DeviceRepository deviceRepository;

    @Mock
    private RedisService redisService;

    @Mock
    private AlgorandService algorandService;

    @Mock
    private JwtService jwtService;

    @Mock
    private VcService vcService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private AnomalyDetectionService anomalyService;

    @Mock
    private EnrollmentMetadataBuilder metadataBuilder;

    private EnrollmentService service;

    @BeforeEach
    void setUp() {
        service = new EnrollmentService(
                deviceRepository,
                redisService,
                algorandService,
                jwtService,
                vcService,
                auditLogService,
                anomalyService,
                metadataBuilder
        );
            org.springframework.test.util.ReflectionTestUtils.setField(service, "nonceTtl", 60L);
    }

    @Test
    void handleFirstContact_whenDeviceNotPending_shouldThrowInvalidDeviceStatusException() {
        Device device = new Device();
        device.setSerialNumber("SN-001");
        device.setStatus(DeviceStatus.ACTIVE);
        when(deviceRepository.findBySerialNumber("SN-001")).thenReturn(Optional.of(device));

        FirstContactRequest request = new FirstContactRequest();
        request.setSerialNumber("SN-001");
        request.setDid("did:algo:ABC");
        request.setPublicKey("ABC");
        request.setSignature("SIG");

        assertThatThrownBy(() -> service.handleFirstContact(request))
                .isInstanceOf(InvalidDeviceStatusException.class)
                .hasMessageContaining("PENDING");
    }

    @Test
    void handleFirstContact_whenMatchingPreRegisteredDevice_shouldIssueNewChallenge() {
        byte[] privateKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String publicKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(privateKey));
        String did = CryptoUtils.buildDid(publicKey, 1010L, "mainnet");
        String serial = "SN-RETRY";

        Device device = new Device();
        device.setSerialNumber(serial);
        device.setDid(did);
        device.setPublicKey(publicKey);
        device.setStatus(DeviceStatus.PRE_REGISTERED);
        when(deviceRepository.findBySerialNumber(serial)).thenReturn(Optional.of(device));

        FirstContactRequest request = new FirstContactRequest();
        request.setSerialNumber(serial);
        request.setDid(did);
        request.setPublicKey(publicKey);
        request.setSignature(CryptoUtils.signEd25519(privateKey, serial + did));

        org.springframework.test.util.ReflectionTestUtils.setField(service, "algorandAppId", 1010L);
        org.springframework.test.util.ReflectionTestUtils.setField(service, "algorandNetwork", "mainnet");

        ChallengeResponse response = service.handleFirstContact(request);

        assertThat(response.getDid()).isEqualTo(did);
        assertThat(response.getNonce()).isNotBlank();
        verify(redisService).saveNonce(did, response.getNonce(), 60L);
        verify(deviceRepository).save(device);
    }

    @Test
    void handleChallengeResponse_whenNonceMissing_shouldThrowNonceExpiredException() {
        when(redisService.getNonce("did:algo:ABC")).thenReturn(null);

        ChallengeResponseRequest request = new ChallengeResponseRequest();
        request.setDid("did:algo:ABC");
        request.setSignedNonce("SIG");

        assertThatThrownBy(() -> service.handleChallengeResponse(request))
                .isInstanceOf(NonceExpiredException.class);

        verify(redisService).getNonce("did:algo:ABC");
    }
}
