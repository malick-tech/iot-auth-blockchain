package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.domain.enums.FailureCategory;
import com.iotauth.iot_auth.dto.request.RevocationRequest;
import com.iotauth.iot_auth.dto.response.DeviceStatusResponse;
import com.iotauth.iot_auth.exception.DeviceNotFoundException;
import com.iotauth.iot_auth.exception.DeviceRevokedException;
import com.iotauth.iot_auth.exception.DeviceSuspendedException;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RevocationService implements DeviceSuspensionPort {

    private final DeviceRepository deviceRepository;
    private final RedisService redisService;
    private final AlgorandService algorandService;
    private final AuditLogService auditLogService;
    private final VcService vcService;
    @Autowired(required = false)
    private AdminKeyService adminKeyService;

    @Value("${iot.auth.redis-ttl-seconds:300}")
    private long redisTtl;

    @Value("${iot.auth.jwt-ttl-seconds:3600}")
    private long jwtTtlSeconds;

    @Override
    @Transactional
    public void suspendDevice(String did, RevocationRequest request) {
        Device device = findDeviceByDid(did);
        suspendDeviceInternal(device, request);
    }

    @Transactional
    public DeviceStatusResponse suspendDeviceAndReturn(String did, RevocationRequest request) {
        Device device = findDeviceByDid(did);
        return suspendDeviceInternal(device, request);
    }

    @Transactional
    public DeviceStatusResponse suspendDeviceBySerialNumber(String serialNumber, RevocationRequest request) {
        Device device = findDeviceBySerialNumber(serialNumber);
        return suspendDeviceInternal(device, request);
    }

    private DeviceStatusResponse suspendDeviceInternal(Device device, RevocationRequest request) {
        validateStatusTransition(device, DeviceStatus.SUSPENDED);
        String did = device.getDid();

        // Pas de transaction Algorand ici : la suspension est rÃ©versible,
        // PostgreSQL en est la source de vÃ©ritÃ©. Le DID reste ACTIVE on-chain
        // pendant toute la durÃ©e de la suspension (cf. rÃ©activation).
        LocalDateTime now = LocalDateTime.now();
        device.setStatus(DeviceStatus.SUSPENDED);
        device.setSuspendedAt(now);
        device.setSuspensionReason(request.getReason());
        Device savedDevice = deviceRepository.save(device);

        // Invalider immédiatement le cache device ET le JWT PoP actif.
        // Sans cette blacklist, la gateway pourrait continuer à autoriser
        // le dispositif pendant toute la durée de vie résiduelle du JWT (jusqu'à 1h).
        redisService.deleteDeviceCache(did);
        redisService.blacklistLastDeviceJwt(did, jwtTtlSeconds);
        auditLogService.record(
                EventType.DEVICE_SUSPENDED,
                did,
                ActorType.ADMIN,
                true,
                "Suspension du dispositif : " + request.getReason(),
                "{\"reason\":\"" + jsonEscape(request.getReason()) + "\",\"targetStatus\":\"SUSPENDED\",\"redisAction\":\"DEL device\"}",
                null
        );

        return toStatusResponse(savedDevice);
    }

    @Transactional
    public DeviceStatusResponse reactivateDevice(String did) {
        Device device = findDeviceByDid(did);
        return reactivateDevice(device);
    }

    @Transactional
    public DeviceStatusResponse reactivateDeviceBySerialNumber(String serialNumber) {
        Device device = findDeviceBySerialNumber(serialNumber);
        return reactivateDevice(device);
    }

    private DeviceStatusResponse reactivateDevice(Device device) {
        validateStatusTransition(device, DeviceStatus.ACTIVE);
        String did = device.getDid();

        // Pas de transaction Algorand ici : le DID est restÃ© ACTIVE on-chain
        // pendant toute la durÃ©e de la suspension (cf. suspendDevice), donc
        // aucune republication n'est nÃ©cessaire ni cohÃ©rente avec ce principe.
        LocalDateTime now = LocalDateTime.now();
        device.setStatus(DeviceStatus.ACTIVE);
        device.setSuspensionReason(null);
        device.setLastSeenAt(now);
        Device savedDevice = deviceRepository.save(device);

        redisService.clearDeviceAuthState(did);

        restoreActiveDeviceCache(savedDevice);

        // Remise Ã  zÃ©ro des compteurs d'anomalies : une rÃ©activation doit
        // repartir sur une fenÃªtre de dÃ©tection propre, sans hÃ©riter des
        // Ã©checs qui ont provoquÃ© la suspension automatique.
        redisService.resetFailures(did, FailureCategory.CHALLENGE);
        redisService.resetFailures(did, FailureCategory.VP);
        redisService.resetFailures(did, FailureCategory.PERMISSION);

        auditLogService.record(
                EventType.DEVICE_REACTIVATED,
                did,
                ActorType.ADMIN,
                true,
                "RÃ©activation du dispositif",
                "{\"targetStatus\":\"ACTIVE\",\"redisAction\":\"RESTORE device\",\"resetFailureCounters\":true}",
                null
        );

        return toStatusResponse(savedDevice);
    }

    @Transactional
    public DeviceStatusResponse revokeDevice(String did, RevocationRequest request) {
        Device device = findDeviceByDid(did);
        return revokeDevice(device, request);
    }

    @Transactional
    public DeviceStatusResponse revokeDeviceBySerialNumber(String serialNumber, RevocationRequest request) {
        Device device = findDeviceBySerialNumber(serialNumber);
        return revokeDevice(device, request);
    }

    private DeviceStatusResponse revokeDevice(Device device, RevocationRequest request) {
        String did = device.getDid();
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

        // Invalider immédiatement le cache device ET le JWT PoP actif.
        // La révocation est irréversible — le token ne doit plus être accepté
        // nulle part, même si la gateway l'a en cache local.
        redisService.deleteDeviceCache(did);
        redisService.blacklistLastDeviceJwt(did, jwtTtlSeconds);
        auditLogService.record(
                EventType.DEVICE_REVOKED,
                did,
                ActorType.ADMIN,
                true,
                "RÃ©vocation du dispositif : " + request.getReason(),
                "{\"reason\":\"" + jsonEscape(request.getReason()) + "\",\"targetStatus\":\"REVOKED\",\"algorandTxId\":\""
                        + jsonEscape(txId) + "\",\"redisAction\":\"DEL device\"}",
                null
        );

        return toStatusResponse(savedDevice);
    }

    @Transactional(readOnly = true)
    public DeviceStatusResponse getDeviceStatus(String did) {
        return toStatusResponse(findDeviceByDid(did));
    }

    @Transactional(readOnly = true)
    public DeviceStatusResponse getDeviceStatusBySerialNumber(String serialNumber) {
        return toStatusResponse(findDeviceBySerialNumber(serialNumber));
    }

    private Device findDeviceByDid(String did) {
        return deviceRepository.findByDid(did)
                .orElseThrow(() -> DeviceNotFoundException.byDid(did));
    }

    private Device findDeviceBySerialNumber(String serialNumber) {
        return deviceRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> DeviceNotFoundException.bySerial(serialNumber));
    }

    private void validateStatusTransition(Device device, DeviceStatus targetStatus) {
        if (device.getStatus() == DeviceStatus.REVOKED) {
            throw DeviceRevokedException.byDid(device.getDid());
        }

        if (targetStatus == DeviceStatus.SUSPENDED) {
            if (device.getStatus() == DeviceStatus.SUSPENDED) throw DeviceSuspendedException.byDid(device.getDid());
            if (device.getStatus() != DeviceStatus.ACTIVE) {
                throw InvalidDeviceStatusException.expected(DeviceStatus.ACTIVE, device.getStatus());
            }
        } else if (targetStatus == DeviceStatus.ACTIVE) {
            if (device.getStatus() != DeviceStatus.SUSPENDED) {
                throw InvalidDeviceStatusException.expected(DeviceStatus.SUSPENDED, device.getStatus());
            }
        }
    }

    private void restoreActiveDeviceCache(Device device) {
        List<String> permissions = vcService.findLatestValidCredential(device.getDid())
                .map(VerifiableCredential::getPermissions)
                .orElse(List.of());
        if (adminKeyService == null) {
            redisService.saveDeviceCache(
                    device.getDid(),
                    device.getPublicKey(),
                    DeviceStatus.ACTIVE.name(),
                    permissions,
                    redisTtl
            );
            return;
        }

        redisService.saveDeviceCache(
                device.getDid(),
                device.getPublicKey(),
                DeviceStatus.ACTIVE.name(),
                permissions,
                issuerPublicKey(),
                issuerDid(),
                redisTtl
        );
    }

    private String issuerPublicKey() {
        return adminKeyService != null ? adminKeyService.getPublicKeyBase32() : null;
    }

    private String issuerDid() {
        return adminKeyService != null ? adminKeyService.getAdminDid() : null;
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

    private String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
