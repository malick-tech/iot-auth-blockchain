package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Size;

public record RevocationRequest(
        @Size(max = 120, message = "deviceId must not exceed 120 characters")
        String deviceId,

        @Size(max = 160, message = "credentialId must not exceed 160 characters")
        String credentialId,

        @Size(max = 512, message = "reason must not exceed 512 characters")
        String reason
) {

    @AssertTrue(message = "deviceId or credentialId is required")
    public boolean hasRevocationTarget() {
        return hasText(deviceId) || hasText(credentialId);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
