package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.enums.AlgorandBoxPrefix;
import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.dto.request.VPRequest;
import com.iotauth.iot_auth.dto.response.ChallengeResponse;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.exception.DeviceNotFoundException;
import com.iotauth.iot_auth.exception.DeviceRevokedException;
import com.iotauth.iot_auth.exception.DeviceSuspendedException;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.exception.InvalidSignatureException;
import com.iotauth.iot_auth.exception.NonceExpiredException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.repository.VcRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock private DeviceRepository deviceRepository;
    @Mock private VcRepository vcRepository;
    @Mock private JwtService jwtService;
    @Mock private VpVerificationService vpVerificationService;
    @Mock private RedisService redisService;
    @Mock private AuditLogService auditLogService;
    @Mock private AnomalyDetectionService anomalyService;
    @Mock private AlgorandService algorandService;
    @Mock private VcService vcService;

    private AuthenticationService service;

    private static final String DID = "did:algo:DEVICE";
    private static final String CHALLENGE = "test-nonce-123";
    private static final String VP = "{\"type\":\"VerifiablePresentation\",\"verifiableCredential\":[{\"id\":\"vc-001\"}]}";
    private static final String SIGNATURE = "base64sig";

    @BeforeEach
    void setUp() {
        service = new AuthenticationService(
                deviceRepository, vcRepository, jwtService,
                vpVerificationService, redisService, auditLogService,
                anomalyService, algorandService, vcService
        );
        ReflectionTestUtils.setField(service, "nonceTtl", 60L);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // issueRenewalChallenge
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void issueRenewalChallenge_whenDeviceActive_shouldReturnNonceAndPersistInRedis() {
        Device device = activeDevice();
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));

        ChallengeResponse response = service.issueRenewalChallenge(DID);

        assertThat(response.getDid()).isEqualTo(DID);
        assertThat(response.getNonce()).isNotBlank();
        verify(redisService).saveNonce(eq(DID), anyString(), eq(60L));
    }

    @Test
    void issueRenewalChallenge_whenDeviceNotFound_shouldThrowDeviceNotFoundException() {
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.issueRenewalChallenge(DID))
                .isInstanceOf(DeviceNotFoundException.class);

        verify(redisService, never()).saveNonce(anyString(), anyString(), anyLong());
    }

    @Test
    void issueRenewalChallenge_whenDeviceSuspended_shouldThrowInvalidDeviceStatusException() {
        Device device = activeDevice();
        device.setStatus(DeviceStatus.SUSPENDED);
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));

        assertThatThrownBy(() -> service.issueRenewalChallenge(DID))
                .isInstanceOf(InvalidDeviceStatusException.class);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // authenticateDevice — cas d'erreur en amont
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void authenticateDevice_whenDeviceNotFound_shouldThrowDeviceNotFoundException() {
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(DeviceNotFoundException.class);
    }

    @Test
    void authenticateDevice_whenDeviceSuspended_shouldThrowDeviceSuspendedException() {
        Device device = activeDevice();
        device.setStatus(DeviceStatus.SUSPENDED);
        device.setSuspensionReason("Maintenance");
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(DeviceSuspendedException.class);
    }

    @Test
    void authenticateDevice_whenDeviceRevoked_shouldThrowDeviceRevokedException() {
        Device device = activeDevice();
        device.setStatus(DeviceStatus.REVOKED);
        device.setRevocationReason("Cle compromise");
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(DeviceRevokedException.class);
    }

    @Test
    void authenticateDevice_whenNonceExpired_shouldThrowNonceExpiredException() {
        Device device = activeDevice();
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn(null);

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(NonceExpiredException.class);
    }

    @Test
    void authenticateDevice_whenChallengeMismatch_shouldThrowInvalidSignatureException() {
        Device device = activeDevice();
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn("other-nonce");

        VPRequest req = vpRequest(); // challenge = "test-nonce-123"

        assertThatThrownBy(() -> service.authenticateDevice(req))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("Challenge");

        // Le nonce doit être consommé même en cas d'échec de comparaison
        verify(redisService).deleteNonce(DID);
    }

    @Test
    void authenticateDevice_whenVpSignatureInvalid_shouldThrowInvalidSignatureException() {
        Device device = activeDevice();
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn(CHALLENGE);
        when(vpVerificationService.verifyPresentation(VP, CHALLENGE, SIGNATURE, device.getPublicKey()))
                .thenReturn(false);

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("VP signature");

        verify(anomalyService).recordVpFailure(DID);
    }

    @Test
    void authenticateDevice_whenVcNotFound_shouldThrowInvalidSignatureException() {
        Device device = activeDevice();
        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn(CHALLENGE);
        when(vpVerificationService.verifyPresentation(VP, CHALLENGE, SIGNATURE, device.getPublicKey()))
                .thenReturn(true);
        when(vpVerificationService.extractVcIdFromPresentation(VP)).thenReturn("vc-001");
        when(vcRepository.findByVcId("vc-001")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("Credential not found");
    }

    @Test
    void authenticateDevice_whenVcExpired_shouldThrowInvalidSignatureException() {
        Device device = activeDevice();
        VerifiableCredential vc = expiredVc();

        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn(CHALLENGE);
        when(vpVerificationService.verifyPresentation(VP, CHALLENGE, SIGNATURE, device.getPublicKey()))
                .thenReturn(true);
        when(vpVerificationService.extractVcIdFromPresentation(VP)).thenReturn("vc-001");
        when(vcRepository.findByVcId("vc-001")).thenReturn(Optional.of(vc));
        when(vcService.verifyIssuerSignature(vc.getRawCredential())).thenReturn(true);

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void authenticateDevice_whenVpReplay_shouldThrowInvalidSignatureException() {
        Device device = activeDevice();
        VerifiableCredential vc = validVc();

        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn(CHALLENGE);
        when(vpVerificationService.verifyPresentation(VP, CHALLENGE, SIGNATURE, device.getPublicKey()))
                .thenReturn(true);
        when(vpVerificationService.extractVcIdFromPresentation(VP)).thenReturn("vc-001");
        when(vcRepository.findByVcId("vc-001")).thenReturn(Optional.of(vc));
        when(vcService.verifyIssuerSignature(vc.getRawCredential())).thenReturn(true);
        when(algorandService.readBox(eq(AlgorandBoxPrefix.STATUS), eq(DID)))
                .thenReturn(Optional.of("ACTIVE".getBytes()));
        when(redisService.isVpUsed(anyString())).thenReturn(true); // replay détecté

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("replay");
    }

    @Test
    void authenticateDevice_whenOnChainStatusNotActive_shouldThrowInvalidSignatureException() {
        Device device = activeDevice();
        VerifiableCredential vc = validVc();

        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn(CHALLENGE);
        when(vpVerificationService.verifyPresentation(VP, CHALLENGE, SIGNATURE, device.getPublicKey()))
                .thenReturn(true);
        when(vpVerificationService.extractVcIdFromPresentation(VP)).thenReturn("vc-001");
        when(vcRepository.findByVcId("vc-001")).thenReturn(Optional.of(vc));
        when(vcService.verifyIssuerSignature(vc.getRawCredential())).thenReturn(true);
        when(algorandService.readBox(eq(AlgorandBoxPrefix.STATUS), eq(DID)))
                .thenReturn(Optional.of("REVOKED".getBytes()));

        assertThatThrownBy(() -> service.authenticateDevice(vpRequest()))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("on-chain");
    }

    @Test
    void authenticateDevice_happyPath_shouldReturnJwtPopResponse() {
        Device device = activeDevice();
        VerifiableCredential vc = validVc();
        JwtPopResponse jwtResponse = new JwtPopResponse();
        jwtResponse.setJwt("header.body.sig");

        when(deviceRepository.findByDid(DID)).thenReturn(Optional.of(device));
        when(redisService.getNonce(DID)).thenReturn(CHALLENGE);
        when(vpVerificationService.verifyPresentation(VP, CHALLENGE, SIGNATURE, device.getPublicKey()))
                .thenReturn(true);
        when(vpVerificationService.extractVcIdFromPresentation(VP)).thenReturn("vc-001");
        when(vcRepository.findByVcId("vc-001")).thenReturn(Optional.of(vc));
        when(vcService.verifyIssuerSignature(vc.getRawCredential())).thenReturn(true);
        when(algorandService.readBox(eq(AlgorandBoxPrefix.STATUS), eq(DID)))
                .thenReturn(Optional.of("ACTIVE".getBytes()));
        when(redisService.isVpUsed(anyString())).thenReturn(false);
        when(jwtService.generateJwtPop(DID, device.getPublicKey())).thenReturn(jwtResponse);
        when(deviceRepository.save(any(Device.class))).thenAnswer(i -> i.getArgument(0));

        JwtPopResponse result = service.authenticateDevice(vpRequest());

        assertThat(result).isNotNull();
        assertThat(result.getJwt()).isEqualTo("header.body.sig");
        verify(redisService).markVpUsed(anyString());
        verify(anomalyService).resetChallengeFailures(DID);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private Device activeDevice() {
        Device d = new Device();
        d.setDid(DID);
        d.setPublicKey("PUBLIC_KEY_BASE32");
        d.setSerialNumber("SN-001");
        d.setStatus(DeviceStatus.ACTIVE);
        return d;
    }

    private VerifiableCredential validVc() {
        VerifiableCredential vc = new VerifiableCredential();
        vc.setVcId("vc-001");
        vc.setSubjectDid(DID);
        vc.setExpirationDate(LocalDateTime.now().plusDays(30));
        vc.setPermissions(List.of("device:read", "device:operate"));
        vc.setRawCredential("{\"id\":\"vc-001\",\"proof\":{}}");
        return vc;
    }

    private VerifiableCredential expiredVc() {
        VerifiableCredential vc = validVc();
        vc.setExpirationDate(LocalDateTime.now().minusDays(1));
        return vc;
    }

    private VPRequest vpRequest() {
        VPRequest req = new VPRequest();
        req.setDid(DID);
        req.setVerifiablePresentation(VP);
        req.setChallenge(CHALLENGE);
        req.setSignature(SIGNATURE);
        return req;
    }
}
