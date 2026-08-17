package com.iotauth.iot_auth.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AdminLoginResponse {
    private String token;
    private String username;
    private long expiresIn;
}