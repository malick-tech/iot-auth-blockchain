package com.iotauth.iot_auth.dto.response;

public record ChallengeResponse(
        String did,
        String nonce,
        long expiresIn
) {
}