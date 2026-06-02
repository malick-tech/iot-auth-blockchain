package com.iotauth.iot_auth.service;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisServiceTest {

    @Test
    void saveNonce_shouldDelegateToRedisTemplate() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        RedisService service = new RedisService(redisTemplate);
        ReflectionTestUtils.invokeMethod(service, "init");

        service.saveNonce("did:algo:ABC", "nonce", 60);

        verify(valueOps).set("nonce:did:algo:ABC", "nonce", Duration.ofSeconds(60));
    }

    @Test
    void getDeviceCache_whenPresent_shouldReturnHashPayload() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        @SuppressWarnings({"rawtypes", "unchecked"})
        HashOperations hashOps = mock(HashOperations.class);
        when(redisTemplate.opsForHash()).thenReturn(hashOps);
        when(hashOps.entries("device:did:algo:ABC")).thenReturn(new HashMap<>(Map.of("status", "ACTIVE")));

        RedisService service = new RedisService(redisTemplate);
        ReflectionTestUtils.invokeMethod(service, "init");

        Optional<Map<String, String>> cache = service.getDeviceCache("did:algo:ABC");

        assertThat(cache).isPresent();
        assertThat(cache.get()).containsEntry("status", "ACTIVE");
    }

    @Test
    void saveDeviceCache_shouldStoreExpectedFields() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        @SuppressWarnings({"rawtypes", "unchecked"})
        HashOperations hashOps = mock(HashOperations.class);
        when(redisTemplate.opsForHash()).thenReturn(hashOps);

        RedisService service = new RedisService(redisTemplate);
        ReflectionTestUtils.invokeMethod(service, "init");

        service.saveDeviceCache("did:algo:ABC", "PUBLIC_KEY", List.of("read", "write"), 300);

        verify(hashOps).putAll(eq("device:did:algo:ABC"), any(Map.class));
        verify(redisTemplate).expire("device:did:algo:ABC", Duration.ofSeconds(300));
    }
}
