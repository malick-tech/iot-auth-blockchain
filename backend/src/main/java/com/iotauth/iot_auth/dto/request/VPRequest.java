package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class VPRequest {

    @NotBlank
    private String did;

    @NotBlank
    private String verifiablePresentation;

    @NotBlank
    private String challenge;

    @NotBlank
    private String signature;
}
