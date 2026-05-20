package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    @Value("${iot.auth.jwt-ttl-seconds:900}")
    private long jwtTtlSeconds;

    public JwtPopResponse generateJwtPop(String did, String publicKey) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(jwtTtlSeconds);
        String token = "dev-token." + did + "." + expiresAt.getEpochSecond();
        return JwtPopResponse.bearer(token, issuedAt, expiresAt, publicKey);
    }
}
