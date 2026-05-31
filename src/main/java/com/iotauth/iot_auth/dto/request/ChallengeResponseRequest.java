package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ChallengeResponseRequest {

    @NotBlank
    private String did;

    @NotBlank
    private String signedNonce;
}
