package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.enums.FailureCategory;
import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.dto.request.RevocationRequest;
import com.iotauth.iot_auth.dto.response.DeviceStatusResponse;
import com.iotauth.iot_auth.exception.DeviceRevokedException;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RevocationServiceTest {

    @Mock
    private DeviceRepository deviceRepository;

    @Mock
    private RedisService redisService;

    @Mock
    private AlgorandService algorandService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private VcService vcService;

    private RevocationService service;

    @BeforeEach
    void setUp() {
        service = new RevocationService(
                deviceRepository,
                redisService,
                algorandService,
                auditLogService,
                vcService
        );
        ReflectionTestUtils.setField(service, "redisTtl", 300L);
        ReflectionTestUtils.setField(service, "jwtTtlSeconds", 3600L);
    }

    @Test
    void suspendDevice_shouldBlacklistJwtImmediately() {
        Device device = activeDevice();
        RevocationRequest request = request("Anomalie");
        when(deviceRepository.findByDid(device.getDid())).thenReturn(Optional.of(device));
        when(deviceRepository.save(any(Device.class))).thenAnswer(i -> i.getArgument(0));

        service.suspendDevice(device.getDid(), request);

        verify(redisService).blacklistLastDeviceJwt(device.getDid(), 3600L);
    }

    @Test
    void revokeDevice_shouldBlacklistJwtImmediately() {
        Device device = activeDevice();
        RevocationRequest request = request("Cle compromise");
        when(deviceRepository.findByDid(device.getDid())).thenReturn(Optional.of(device));
        when(algorandService.publishDeviceLifecycleEvent(device.getDid(), "REVOKED", request.getReason()))
                .thenReturn("tx-revoke");
        when(deviceRepository.save(any(Device.class))).thenAnswer(i -> i.getArgument(0));

        service.revokeDevice(device.getDid(), request);

        verify(redisService).blacklistLastDeviceJwt(device.getDid(), 3600L);
    }

    @Test
    void suspendDevice_whenActive_shouldSuspendAndEvictCache() {
        Device device = activeDevice();
        RevocationRequest request = request("Maintenance securite");
        when(deviceRepository.findByDid(device.getDid())).thenReturn(Optional.of(device));
        when(deviceRepository.save(any(Device.class))).thenAnswer(invocation -> invocation.getArgument(0));

        DeviceStatusResponse response = service.suspendDeviceAndReturn(device.getDid(), request);

        assertThat(response.getStatus()).isEqualTo(DeviceStatus.SUSPENDED);
        assertThat(response.isSuspended()).isTrue();
        assertThat(device.getSuspensionReason()).isEqualTo("Maintenance securite");
        assertThat(device.getAlgorandTxId()).isNull();
        verify(redisService).deleteDeviceCache(device.getDid());
        verifyNoInteractions(algorandService);
        verify(auditLogService).record(
                eq(EventType.DEVICE_SUSPENDED),
                eq(device.getDid()),
                eq(ActorType.ADMIN),
                eq(true),
                any(String.class),
                contains("\"targetStatus\":\"SUSPENDED\""),
                eq(null)
        );
    }

    @Test
    void reactivateDevice_whenSuspended_shouldActivateAndRestoreCache() {
        Device device = activeDevice();
        device.setStatus(DeviceStatus.SUSPENDED);
        device.setSuspensionReason("Pause");
        VerifiableCredential vc = new VerifiableCredential();
        vc.setPermissions(List.of("device:read"));

        when(deviceRepository.findByDid(device.getDid())).thenReturn(Optional.of(device));
        when(deviceRepository.save(any(Device.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(vcService.findLatestValidCredential(device.getDid())).thenReturn(Optional.of(vc));

        DeviceStatusResponse response = service.reactivateDevice(device.getDid());

        assertThat(response.getStatus()).isEqualTo(DeviceStatus.ACTIVE);
        assertThat(response.isActive()).isTrue();
        assertThat(device.getSuspensionReason()).isNull();
        verify(redisService).saveDeviceCache(device.getDid(), device.getPublicKey(), "ACTIVE", List.of("device:read"), 300L);
        verify(redisService).clearDeviceAuthState(device.getDid());
        verify(redisService).resetFailures(device.getDid(), FailureCategory.CHALLENGE);
        verify(redisService).resetFailures(device.getDid(), FailureCategory.VP);
        verify(redisService).resetFailures(device.getDid(), FailureCategory.PERMISSION);
        verifyNoInteractions(algorandService);
        verify(auditLogService).record(
                eq(EventType.DEVICE_REACTIVATED),
                eq(device.getDid()),
                eq(ActorType.ADMIN),
                eq(true),
                any(String.class),
                contains("\"resetFailureCounters\":true"),
                eq(null)
        );
    }

    @Test
    void revokeDevice_whenActive_shouldRevokeAndEvictCache() {
        Device device = activeDevice();
        RevocationRequest request = request("Cle compromise");
        when(deviceRepository.findByDid(device.getDid())).thenReturn(Optional.of(device));
        when(algorandService.publishDeviceLifecycleEvent(device.getDid(), "REVOKED", request.getReason()))
                .thenReturn("tx-revoke");
        when(deviceRepository.save(any(Device.class))).thenAnswer(invocation -> invocation.getArgument(0));

        DeviceStatusResponse response = service.revokeDevice(device.getDid(), request);

        assertThat(response.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(response.isRevoked()).isTrue();
        assertThat(device.getRevocationReason()).isEqualTo("Cle compromise");
        verify(redisService).deleteDeviceCache(device.getDid());
        verify(algorandService).publishDeviceLifecycleEvent(device.getDid(), "REVOKED", request.getReason());
        verify(auditLogService).record(
                eq(EventType.DEVICE_REVOKED),
                eq(device.getDid()),
                eq(ActorType.ADMIN),
                eq(true),
                any(String.class),
                contains("\"algorandTxId\":\"tx-revoke\""),
                eq(null)
        );
    }

    @Test
    void revokeDeviceBySerialNumber_whenActive_shouldUseSerialNumberLookup() {
        Device device = activeDevice();
        RevocationRequest request = request("Test Postman");
        when(deviceRepository.findBySerialNumber(device.getSerialNumber())).thenReturn(Optional.of(device));
        when(algorandService.publishDeviceLifecycleEvent(device.getDid(), "REVOKED", request.getReason()))
                .thenReturn("tx-revoke");
        when(deviceRepository.save(any(Device.class))).thenAnswer(invocation -> invocation.getArgument(0));

        DeviceStatusResponse response = service.revokeDeviceBySerialNumber(device.getSerialNumber(), request);

        assertThat(response.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        verify(deviceRepository).findBySerialNumber("SN-001");
        verify(redisService).deleteDeviceCache(device.getDid());
        verify(algorandService).publishDeviceLifecycleEvent(device.getDid(), "REVOKED", request.getReason());
    }

    @Test
    void suspendDevice_whenPending_shouldThrowInvalidDeviceStatusException() {
        Device device = activeDevice();
        device.setStatus(DeviceStatus.PENDING);
        when(deviceRepository.findByDid(device.getDid())).thenReturn(Optional.of(device));

        assertThatThrownBy(() -> service.suspendDeviceAndReturn(device.getDid(), request("Non pret")))
                .isInstanceOf(InvalidDeviceStatusException.class);

        verifyNoInteractions(redisService, algorandService);
    }

    @Test
    void reactivateDevice_whenRevoked_shouldThrowDeviceRevokedException() {
        Device device = activeDevice();
        device.setStatus(DeviceStatus.REVOKED);
        when(deviceRepository.findByDid(device.getDid())).thenReturn(Optional.of(device));

        assertThatThrownBy(() -> service.reactivateDevice(device.getDid()))
                .isInstanceOf(DeviceRevokedException.class);

        verifyNoInteractions(redisService, algorandService);
    }

    private Device activeDevice() {
        Device device = new Device();
        device.setId(1L);
        device.setDid("did:algo:DEVICE");
        device.setPublicKey("PUBLIC_KEY");
        device.setSerialNumber("SN-001");
        device.setStatus(DeviceStatus.ACTIVE);
        return device;
    }

    private RevocationRequest request(String reason) {
        RevocationRequest request = new RevocationRequest();
        request.setReason(reason);
        return request;
    }
}
