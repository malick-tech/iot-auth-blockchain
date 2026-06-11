package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class FirstContactRequest {

    @NotBlank
    private String serialNumber;

    @NotBlank
    private String did;

    @NotBlank
    private String publicKey;

    @NotBlank
    private String signature;
}
