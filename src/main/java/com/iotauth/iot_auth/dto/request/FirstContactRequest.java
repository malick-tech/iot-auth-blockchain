package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record FirstContactRequest(
        @NotBlank(message = "deviceId is required")
        @Size(max = 120, message = "deviceId must not exceed 120 characters")
        String deviceId
) {
}
