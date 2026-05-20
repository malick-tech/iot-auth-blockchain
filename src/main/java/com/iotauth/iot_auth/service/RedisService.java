package com.iotauth.iot_auth.service;

import java.time.Duration;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final StringRedisTemplate redisTemplate;

    public void saveNonce(String did, String nonce, long ttlSeconds) {
        redisTemplate.opsForValue().set(nonceKey(did), nonce, Duration.ofSeconds(ttlSeconds));
    }

    public String getNonce(String did) {
        return redisTemplate.opsForValue().get(nonceKey(did));
    }

    public void deleteNonce(String did) {
        redisTemplate.delete(nonceKey(did));
    }

    public void saveDeviceCache(String did, String publicKey, String permissions, long ttlSeconds) {
        redisTemplate.opsForHash().putAll(deviceKey(did), Map.of(
                "publicKey", publicKey,
                "permissions", permissions == null ? "" : permissions
        ));
        redisTemplate.expire(deviceKey(did), Duration.ofSeconds(ttlSeconds));
    }

    public void resetFailures(String did, String category) {
        redisTemplate.delete(failureKey(did, category));
    }

    private String nonceKey(String did) {
        return "iot:nonce:" + did;
    }

    private String deviceKey(String did) {
        return "iot:device:" + did;
    }

    private String failureKey(String did, String category) {
        return "iot:failures:" + category + ":" + did;
    }
}
