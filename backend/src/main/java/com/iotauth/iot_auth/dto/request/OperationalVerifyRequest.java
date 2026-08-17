package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OperationalVerifyRequest {

    @NotBlank
    private String did;

    @NotBlank
    private String jwt;

    private long timestamp;

    @NotBlank
    private String proofSignature;

    private String requestedPermission;
}