package com.iotauth.iot_auth.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ChallengeResponse {
    private String nonce;
    private String did;
    private long expiresIn;
}
