package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChallengeAnswerRequest(
        @NotBlank(message = "did is required")
        @Size(max = 180, message = "did must not exceed 180 characters")
        String did,

        @NotBlank(message = "signedNonce is required")
        String signedNonce
) {
}
