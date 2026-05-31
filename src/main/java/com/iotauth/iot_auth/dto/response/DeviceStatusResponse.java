package com.iotauth.iot_auth.dto.response;

import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class DeviceStatusResponse {
    private String did;
    private DeviceStatus status;
    private boolean active;
    private boolean suspended;
    private boolean revoked;
    private String algorandTxId;
    private LocalDateTime lastSeenAt;
}
