package com.iotauth.iot_auth.dto.response;

import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class DeviceResponse {
    private Long id;
    private String serialNumber;
    private String macAddress;
    private String did;
    private String publicKey;
    private DeviceStatus status;
    private String algorandTxId;
    private String deviceType;
    private String location;
    private String logicalGroup;
    private String responsible;
    private LocalDateTime activatedAt;
    private LocalDateTime suspendedAt;
    private String suspensionReason;
    private LocalDateTime revokedAt;
    private String revocationReason;
    private LocalDateTime lastSeenAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
