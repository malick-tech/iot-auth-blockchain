package com.iotauth.iot_auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final StringRedisTemplate redisTemplate;

    private HashOperations<String, String, String> hashOps;
    private ValueOperations<String, String> valueOps;

    @PostConstruct
    private void init() {
        this.hashOps = redisTemplate.opsForHash();
        this.valueOps = redisTemplate.opsForValue();
    }

    // ============= Nonce Management =============

    public void saveNonce(String did, String nonce, long ttlSeconds) {
        valueOps.set(nonceKey(did), nonce, Duration.ofSeconds(ttlSeconds));
    }

    public String getNonce(String did) {
        return valueOps.get(nonceKey(did));
    }

    public void deleteNonce(String did) {
        redisTemplate.delete(nonceKey(did));
    }

    // ============= Device Cache Management =============

    public void saveDeviceCache(String did, String publicKey, List<String> permissions, long ttlSeconds) {
        saveDeviceCache(did, publicKey, "ACTIVE", permissions, ttlSeconds);
    }

    public void saveDeviceCache(
            String did,
            String publicKey,
            List<String> permissions,
            String issuerPublicKey,
            String issuerDid,
            long ttlSeconds
    ) {
        saveDeviceCache(did, publicKey, "ACTIVE", permissions, issuerPublicKey, issuerDid, ttlSeconds);
    }

    public void saveDeviceCache(
            String did,
            String publicKey,
            String status,
            List<String> permissions,
            long ttlSeconds
    ) {
        saveDeviceCache(did, publicKey, status, permissions, null, null, ttlSeconds);
    }

    public void saveDeviceCache(
            String did,
            String publicKey,
            String status,
            List<String> permissions,
            String issuerPublicKey,
            String issuerDid,
            long ttlSeconds
    ) {
        Map<String, String> payload = new HashMap<>();
        payload.put("publicKey", publicKey);
        payload.put("status", status);
        payload.put("permissions", String.join(",", permissions));
        if (issuerPublicKey != null && !issuerPublicKey.isBlank()) {
            payload.put("issuerPublicKey", issuerPublicKey);
        }
        if (issuerDid != null && !issuerDid.isBlank()) {
            payload.put("issuerDid", issuerDid);
        }
        hashOps.putAll(deviceKey(did), payload);
        redisTemplate.expire(deviceKey(did), Duration.ofSeconds(ttlSeconds));
    }

    public Optional<Map<String, String>> getDeviceCache(String did) {
        Map<String, String> cache = hashOps.entries(deviceKey(did));
        if (cache == null || cache.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(cache);
    }

    public boolean isDeviceCached(String did) {
        Boolean exists = redisTemplate.hasKey(deviceKey(did));
        return Boolean.TRUE.equals(exists);
    }

    public void deleteDeviceCache(String did) {
        redisTemplate.delete(deviceKey(did));
    }

    // ============= Failure Tracking (Anomaly Detection) =============

    public long incrementFailures(String did, String reason, long ttlSeconds) {
        Long count = valueOps.increment(failureKey(did, reason));
        redisTemplate.expire(failureKey(did, reason), Duration.ofSeconds(ttlSeconds));
        return count != null ? count : 0;
    }

    public long getFailures(String did, String reason) {
        String value = valueOps.get(failureKey(did, reason));
        if (value == null) {
            return 0;
        }
        return Long.parseLong(value);
    }

    public void resetFailures(String did, String reason) {
        redisTemplate.delete(failureKey(did, reason));
    }

    // ============= VP Replay Prevention =============

    /**
     * Marks a Verifiable Presentation as used to prevent replay attacks.
     * TTL is set to ensure old VPs expire from cache.
     *
     * @param vpHash SHA-256 hash of the VP
     */
    public void markVpUsed(String vpHash) {
        // VP cache kept for 1 hour (same as JWT TTL) to prevent replay
        valueOps.set(vpKey(vpHash), "used", Duration.ofHours(1));
    }

    /**
     * Checks if a VP has already been used.
     *
     * @param vpHash SHA-256 hash of the VP
     * @return true if VP was already used
     */
    public boolean isVpUsed(String vpHash) {
        Boolean exists = redisTemplate.hasKey(vpKey(vpHash));
        return Boolean.TRUE.equals(exists);
    }

    // ============= JWT Token Caching (Optional) =============

    /**
     * Caches a JWT token for quick verification.
     * Useful for Gateway to verify tokens locally without querying backend.
     *
     * @param jti JWT ID (unique identifier)
     * @param token JWT token
     * @param ttlSeconds TTL in seconds
     */
    public void cacheJwtToken(String jti, String token, long ttlSeconds) {
        valueOps.set(jwtKey(jti), token, Duration.ofSeconds(ttlSeconds));
    }

    /**
     * Retrieves a cached JWT token.
     *
     * @param jti JWT ID
     * @return token if cached, null otherwise
     */
    public String getCachedJwtToken(String jti) {
        return valueOps.get(jwtKey(jti));
    }

    /**
     * Blacklists a JWT token (useful for logout).
     *
     * @param jti JWT ID
     * @param ttlSeconds TTL in seconds
     */
    public void blacklistJwtToken(String jti, long ttlSeconds) {
        valueOps.set(jwtBlacklist(jti), "blacklisted", Duration.ofSeconds(ttlSeconds));
    }

    /**
     * Checks if a JWT token is blacklisted.
     *
     * @param jti JWT ID
     * @return true if token is blacklisted
     */
    public boolean isJwtBlacklisted(String jti) {
        Boolean exists = redisTemplate.hasKey(jwtBlacklist(jti));
        return Boolean.TRUE.equals(exists);
    }

    // ============= Key Prefix Helpers =============

    private String nonceKey(String did) {
        return "nonce:" + did;
    }

    private String deviceKey(String did) {
        return "device:" + did;
    }

    private String failureKey(String did, String reason) {
        return "failures:" + did + ":" + reason;
    }

    private String vpKey(String vpHash) {
        return "vp_used:" + vpHash;
    }

    private String jwtKey(String jti) {
        return "jwt:" + jti;
    }

    private String jwtBlacklist(String jti) {
        return "jwt_blacklist:" + jti;
    }
}
