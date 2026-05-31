package com.iotauth.iot_auth.dto.response;

import lombok.Data;

import java.time.Instant;

@Data
public class JwtPopResponse {
    private String jwt;
    private String tokenType = "PoP";
    private String did;
    private long expiresIn;
    private Instant expiresAt;
}
