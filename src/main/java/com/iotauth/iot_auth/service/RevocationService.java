package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.dto.request.RevocationRequest;
import com.iotauth.iot_auth.dto.response.DeviceStatusResponse;
import com.iotauth.iot_auth.exception.DeviceNotFoundException;
import com.iotauth.iot_auth.exception.DeviceRevokedException;
import com.iotauth.iot_auth.exception.DeviceSuspendedException;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RevocationService {

    private final DeviceRepository deviceRepository;
    private final RedisService redisService;
    private final AlgorandService algorandService;
    private final AuditLogService auditLogService;
    private final VcService vcService;

    @Value("${iot.auth.redis-ttl-seconds:300}")
    private long redisTtl;

    @Transactional
    public DeviceStatusResponse suspendDevice(String did, RevocationRequest request) {
        Device device = findDeviceByDid(did);
        ensureNotRevoked(device);

        if (device.getStatus() == DeviceStatus.SUSPENDED) {
            throw DeviceSuspendedException.byDid(did);
        }
        if (device.getStatus() != DeviceStatus.ACTIVE) {
            throw InvalidDeviceStatusException.expected(DeviceStatus.ACTIVE, device.getStatus());
        }

        String txId = algorandService.publishDeviceLifecycleEvent(did, DeviceStatus.SUSPENDED.name(), request.getReason());
        LocalDateTime now = LocalDateTime.now();
        device.setStatus(DeviceStatus.SUSPENDED);
        device.setSuspendedAt(now);
        device.setSuspensionReason(request.getReason());
        device.setAlgorandTxId(txId);
        Device savedDevice = deviceRepository.save(device);

        redisService.deleteDeviceCache(did);
        auditLogService.record(
                EventType.DEVICE_SUSPENDED,
                did,
                ActorType.ADMIN,
                true,
                "Suspension du dispositif : " + request.getReason()
        );

        return toStatusResponse(savedDevice);
    }

    @Transactional
    public DeviceStatusResponse reactivateDevice(String did) {
        Device device = findDeviceByDid(did);
        ensureNotRevoked(device);

        if (device.getStatus() != DeviceStatus.SUSPENDED) {
            throw InvalidDeviceStatusException.expected(DeviceStatus.SUSPENDED, device.getStatus());
        }

        String txId = algorandService.publishDeviceLifecycleEvent(did, DeviceStatus.ACTIVE.name(), "Reactivation");
        device.setStatus(DeviceStatus.ACTIVE);
        device.setAlgorandTxId(txId);
        device.setSuspensionReason(null);
        Device savedDevice = deviceRepository.save(device);

        restoreActiveDeviceCache(savedDevice);
        auditLogService.record(
                EventType.DEVICE_REACTIVATED,
                did,
                ActorType.ADMIN,
                true,
                "Reactivation du dispositif"
        );

        return toStatusResponse(savedDevice);
    }

    @Transactional
    public DeviceStatusResponse revokeDevice(String did, RevocationRequest request) {
        Device device = findDeviceByDid(did);
        if (device.getStatus() == DeviceStatus.REVOKED) {
            throw DeviceRevokedException.byDid(did);
        }

        String txId = algorandService.publishDeviceLifecycleEvent(did, DeviceStatus.REVOKED.name(), request.getReason());
        LocalDateTime now = LocalDateTime.now();
        device.setStatus(DeviceStatus.REVOKED);
        device.setRevokedAt(now);
        device.setRevocationReason(request.getReason());
        device.setAlgorandTxId(txId);
        Device savedDevice = deviceRepository.save(device);

        redisService.deleteDeviceCache(did);
        auditLogService.record(
                EventType.DEVICE_REVOKED,
                did,
                ActorType.ADMIN,
                true,
                "Revocation du dispositif : " + request.getReason()
        );

        return toStatusResponse(savedDevice);
    }

    @Transactional(readOnly = true)
    public DeviceStatusResponse getDeviceStatus(String did) {
        return toStatusResponse(findDeviceByDid(did));
    }

    private Device findDeviceByDid(String did) {
        return deviceRepository.findByDid(did)
                .orElseThrow(() -> DeviceNotFoundException.byDid(did));
    }

    private void ensureNotRevoked(Device device) {
        if (device.getStatus() == DeviceStatus.REVOKED) {
            throw DeviceRevokedException.byDid(device.getDid());
        }
    }

    private void restoreActiveDeviceCache(Device device) {
        List<String> permissions = vcService.findLatestValidCredential(device.getDid())
                .map(VerifiableCredential::getPermissions)
                .orElse(List.of());
        redisService.saveDeviceCache(
                device.getDid(),
                device.getPublicKey(),
                DeviceStatus.ACTIVE.name(),
                permissions,
                redisTtl
        );
    }

    private DeviceStatusResponse toStatusResponse(Device device) {
        return DeviceStatusResponse.builder()
                .did(device.getDid())
                .status(device.getStatus())
                .active(device.getStatus() == DeviceStatus.ACTIVE)
                .suspended(device.getStatus() == DeviceStatus.SUSPENDED)
                .revoked(device.getStatus() == DeviceStatus.REVOKED)
                .algorandTxId(device.getAlgorandTxId())
                .lastSeenAt(device.getLastSeenAt())
                .build();
    }
}
