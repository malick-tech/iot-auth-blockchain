package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.repository.DeviceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceInactivityMonitorService {

    private final DeviceRepository deviceRepository;
    private final RedisService redisService;
    private final AuditLogService auditLogService;

    @Value("${iot.auth.inactivity-monitor.enabled:true}")
    private boolean enabled;

    @Value("${iot.auth.inactivity-monitor.timeout-seconds:90}")
    private long timeoutSeconds;

    @Value("${iot.auth.jwt-ttl-seconds:3600}")
    private long jwtTtlSeconds;

    @Scheduled(
            initialDelayString = "${iot.auth.inactivity-monitor.initial-delay-ms:30000}",
            fixedDelayString = "${iot.auth.inactivity-monitor.scan-interval-ms:30000}"
    )
    @Transactional
    public void suspendInactiveDevices() {
        if (!enabled) {
            return;
        }

        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(timeoutSeconds);
        List<Device> inactiveDevices = deviceRepository.findByStatusAndLastSeenAtBeforeOrNull(DeviceStatus.ACTIVE, cutoff);

        for (Device device : inactiveDevices) {
            suspendInactiveDevice(device, cutoff);
        }
    }

    private void suspendInactiveDevice(Device device, LocalDateTime cutoff) {
        String reason = "Suspension automatique : aucun signal recu depuis plus de "
                + timeoutSeconds + " secondes";

        device.setStatus(DeviceStatus.SUSPENDED);
        device.setSuspendedAt(LocalDateTime.now());
        device.setSuspensionReason(reason);
        deviceRepository.save(device);

        // Invalider immédiatement le cache device ET le JWT PoP actif pour que
        // la gateway ne puisse plus autoriser ce dispositif inactif même en cache HIT.
        redisService.deleteDeviceCache(device.getDid());
        redisService.blacklistLastDeviceJwt(device.getDid(), jwtTtlSeconds);

        auditLogService.record(
                EventType.DEVICE_AUTO_SUSPENDED,
                device.getDid(),
                ActorType.SYSTEM,
                true,
                reason,
                "{\"serialNumber\":\"" + jsonEscape(device.getSerialNumber())
                        + "\",\"lastSeenAt\":\"" + device.getLastSeenAt()
                        + "\",\"cutoff\":\"" + cutoff
                        + "\",\"timeoutSeconds\":" + timeoutSeconds
                        + ",\"targetStatus\":\"SUSPENDED\",\"redisAction\":\"DEL device\"}",
                null
        );

        log.warn("Device auto-suspended for inactivity: serial={}, did={}, lastSeenAt={}",
                device.getSerialNumber(), device.getDid(), device.getLastSeenAt());
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
