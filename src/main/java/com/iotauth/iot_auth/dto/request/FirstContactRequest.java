package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record FirstContactRequest(
        @NotBlank(message = "deviceId is required")
        @Size(max = 120, message = "deviceId must not exceed 120 characters")
        String deviceId,

        @NotBlank(message = "did is required")
        @Size(max = 180, message = "did must not exceed 180 characters")
        String did,

        @NotBlank(message = "publicKey is required")
        @Size(max = 512, message = "publicKey must not exceed 512 characters")
        String publicKey,

        @NotBlank(message = "signature is required")
        String signature
) {
}
