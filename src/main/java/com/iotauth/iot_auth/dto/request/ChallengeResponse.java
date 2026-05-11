package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public record ChallengeResponse(
        @NotBlank(message = "deviceId is required")
        @Size(max = 120, message = "deviceId must not exceed 120 characters")
        String deviceId,

        @NotBlank(message = "nonce is required")
        @Size(max = 180, message = "nonce must not exceed 180 characters")
        String nonce,

        @NotNull(message = "timestamp is required")
        Instant timestamp,

        @NotBlank(message = "signature is required")
        String signature,

        @NotBlank(message = "algorithm is required")
        @Size(max = 40, message = "algorithm must not exceed 40 characters")
        String algorithm
) {
}
