package com.iotauth.iot_auth.dto.response;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import java.time.Instant;

public record DeviceResponse(
        Long id,
        String deviceId,
        String did,
        DeviceStatus status,
        Instant createdAt,
        Instant updatedAt,
        Instant lastSeenAt
) {

    public static DeviceResponse fromEntity(Device device) {
        return new DeviceResponse(
                device.getId(),
                device.getDeviceId(),
                device.getDid(),
                device.getStatus(),
                device.getCreatedAt(),
                device.getUpdatedAt(),
                device.getLastSeenAt()
        );
    }
}
