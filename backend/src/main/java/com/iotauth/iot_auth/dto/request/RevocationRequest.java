package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RevocationRequest {

    @NotBlank
    private String reason;
}
