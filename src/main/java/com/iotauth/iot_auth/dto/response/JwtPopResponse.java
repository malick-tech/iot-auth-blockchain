package com.iotauth.iot_auth.dto.response;

import java.time.Instant;

public record JwtPopResponse(
        String tokenType,
        String accessToken,
        Instant issuedAt,
        Instant expiresAt,
        String proofOfPossessionKeyId
) {

    public static JwtPopResponse bearer(String accessToken, Instant issuedAt, Instant expiresAt, String keyId) {
        return new JwtPopResponse("Bearer", accessToken, issuedAt, expiresAt, keyId);
    }
}
