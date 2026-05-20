package com.iotauth.iot_auth.dto.response;

import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import java.time.Instant;

public record DeviceStatusResponse(
        String deviceId,
        DeviceStatus status,
        boolean revoked,
        boolean suspended,
        Instant lastSeenAt
) {
}
