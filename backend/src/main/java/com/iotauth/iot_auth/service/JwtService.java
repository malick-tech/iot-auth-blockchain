package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.util.CryptoUtils;
import com.iotauth.iot_auth.exception.InvalidSignatureException;
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
        jwtPopResponse.setTokenType("Bearer");
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

    /**
     * Décode et vérifie la signature d'un JWT PoP (signé par l'Admin/Spring Boot).
     * Ne vérifie PAS la preuve de possession du dispositif - juste l'authenticité du token.
     */
    public JwtClaims verifyJwtPop(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new InvalidSignatureException("Format de JWT PoP invalide");
        }

        String signingInput = parts[0] + "." + parts[1];
        boolean sigValid = CryptoUtils.verifyEd25519(
                adminKeyService.getPublicKeyBase32(),
                signingInput,
                parts[2]
        );
        if (!sigValid) {
            throw new InvalidSignatureException("Signature du JWT PoP invalide");
        }

        String payloadJson = new String(
                Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
        );

        try {
            Map<String, Object> payload = readJsonMap(payloadJson);
            return JwtClaims.from(payload);
        } catch (JsonProcessingException e) {
            throw new InvalidSignatureException("Payload du JWT PoP illisible");
        }
    }

    public Map<String, Object> readJsonMap(String json) throws JsonProcessingException {
        return objectMapper.readValue(json, Map.class);
    }

    public static class JwtClaims {
        private final String sub;
        private final String iss;
        private final long iat;
        private final long exp;
        private final String jti;

        private JwtClaims(String sub, String iss, long iat, long exp, String jti) {
            this.sub = sub;
            this.iss = iss;
            this.iat = iat;
            this.exp = exp;
            this.jti = jti;
        }

        static JwtClaims from(Map<String, Object> payload) {
            return new JwtClaims(
                    (String) payload.get("sub"),
                    (String) payload.get("iss"),
                    ((Number) payload.get("iat")).longValue(),
                    ((Number) payload.get("exp")).longValue(),
                    (String) payload.get("jti")
            );
        }

        public String getSub() { return sub; }
        public String getIss() { return iss; }
        public long getIat() { return iat; }
        public long getExp() { return exp; }
        public String getJti() { return jti; }
    }
}
