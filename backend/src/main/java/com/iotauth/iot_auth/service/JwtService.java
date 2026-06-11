package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final AdminKeyService adminKeyService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${iot.auth.jwt-ttl-seconds:3600}")
    private long jwtTtlSeconds;

    public JwtPopResponse generateJwtPop(String did, String publicKeyBase32) {
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(jwtTtlSeconds);

        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", base64EncodePublicKey(publicKeyBase32));

        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", jwk);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", did);
        payload.put("iss", adminKeyService.getAdminDid());
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", expiration.getEpochSecond());
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("cnf", cnf);

        String header = base64UrlEncode(mapToJson(Map.of("alg", "EdDSA", "typ", "JWT")));
        String body = base64UrlEncode(mapToJson(payload));
        String signingInput = header + "." + body;
        String signature = adminKeyService.sign(signingInput);

        JwtPopResponse jwtPopResponse = new JwtPopResponse();
        jwtPopResponse.setJwt(signingInput + "." + signature);
        jwtPopResponse.setDid(did);
        jwtPopResponse.setExpiresIn(jwtTtlSeconds);
        jwtPopResponse.setExpiresAt(expiration);
        return jwtPopResponse;
    }

    private String base64UrlEncode(String data) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    private String mapToJson(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Impossible de sérialiser le JWT PoP", e);
        }
    }

    private String base64EncodePublicKey(String publicKeyBase32) {
        return CryptoUtils.encodeBase64Standard(CryptoUtils.decodeBase32(publicKeyBase32));
    }
}
