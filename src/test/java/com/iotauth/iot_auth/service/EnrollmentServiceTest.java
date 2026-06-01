package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.dto.request.ChallengeResponseRequest;
import com.iotauth.iot_auth.dto.request.FirstContactRequest;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.exception.NonceExpiredException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
                anomalyService
        );
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
