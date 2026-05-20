package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record VPRequest(
        @NotBlank(message = "deviceId is required")
        @Size(max = 120, message = "deviceId must not exceed 120 characters")
        String deviceId,

        @NotBlank(message = "credentialId is required")
        @Size(max = 160, message = "credentialId must not exceed 160 characters")
        String credentialId,

        @NotBlank(message = "verifiablePresentationJson is required")
        String verifiablePresentationJson,

        @NotBlank(message = "challenge is required")
        @Size(max = 180, message = "challenge must not exceed 180 characters")
        String challenge,

        @NotBlank(message = "signature is required")
        String signature
) {
}
