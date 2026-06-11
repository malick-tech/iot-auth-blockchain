package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DeviceRegisterRequest {

    @NotBlank
    private String serialNumber;

    private String macAddress;

    @NotBlank
    private String deviceType;

    @NotBlank
    private String location;

    private String logicalGroup;
    private String responsible;
}
