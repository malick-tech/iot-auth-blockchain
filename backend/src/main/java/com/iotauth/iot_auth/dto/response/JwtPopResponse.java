package com.iotauth.iot_auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtPopResponse {
    private String jwtToken;
    private String tokenType;
    private String did;
    private long expiresIn;
    private Instant expiresAt;
    private List<String> permissions;
    private String credentialId;
    private String verifiableCredential;
    private String deviceSerialNumber;

    // Legacy field names for backward compatibility
    @Deprecated
    private String jwt;

    public String getJwt() {
        return jwtToken != null ? jwtToken : jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
        if (this.jwtToken == null) {
            this.jwtToken = jwt;
        }
    }
}
