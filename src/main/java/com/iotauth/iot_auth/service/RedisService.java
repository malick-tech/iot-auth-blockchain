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

    public void saveNonce(String did, String nonce, long ttlSeconds) {
        valueOps.set(nonceKey(did), nonce, Duration.ofSeconds(ttlSeconds));
    }

    public String getNonce(String did) {
        return valueOps.get(nonceKey(did));
    }

    public void deleteNonce(String did) {
        redisTemplate.delete(nonceKey(did));
    }

    public void saveDeviceCache(String did, String publicKey, List<String> permissions, long ttlSeconds) {
        saveDeviceCache(did, publicKey, "ACTIVE", permissions, ttlSeconds);
    }

    public void saveDeviceCache(
            String did,
            String publicKey,
            String status,
            List<String> permissions,
            long ttlSeconds
    ) {
        Map<String, String> payload = new HashMap<>();
        payload.put("publicKey", publicKey);
        payload.put("status", status);
        payload.put("permissions", String.join(",", permissions));
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

    private String nonceKey(String did) {
        return "nonce:" + did;
    }

    private String deviceKey(String did) {
        return "device:" + did;
    }

    private String failureKey(String did, String reason) {
        return "failures:" + did + ":" + reason;
    }
}
