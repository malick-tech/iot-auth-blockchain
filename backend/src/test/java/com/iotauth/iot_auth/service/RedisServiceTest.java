package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.enums.FailureCategory;
import org.junit.jupiter.api.BeforeEach;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisServiceTest {

    private StringRedisTemplate redisTemplate;
    @SuppressWarnings({"rawtypes", "unchecked"})
    private HashOperations hashOps;
    private ValueOperations<String, String> valueOps;
    private RedisService service;

    @BeforeEach
    @SuppressWarnings({"rawtypes", "unchecked"})
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        hashOps = mock(HashOperations.class);
        valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForHash()).thenReturn(hashOps);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        service = new RedisService(redisTemplate);
        ReflectionTestUtils.invokeMethod(service, "init");
    }

    // ── Nonce ────────────────────────────────────────────────────────────────

    @Test
    void saveNonce_shouldDelegateToValueOps() {
        service.saveNonce("did:algo:ABC", "nonce42", 60);
        verify(valueOps).set("nonce:did:algo:ABC", "nonce42", Duration.ofSeconds(60));
    }

    @Test
    void getNonce_shouldReturnStoredValue() {
        when(valueOps.get("nonce:did:algo:ABC")).thenReturn("my-nonce");
        assertThat(service.getNonce("did:algo:ABC")).isEqualTo("my-nonce");
    }

    @Test
    void deleteNonce_shouldDeleteKey() {
        service.deleteNonce("did:algo:ABC");
        verify(redisTemplate).delete("nonce:did:algo:ABC");
    }

    // ── Device cache ─────────────────────────────────────────────────────────

    @Test
    void getDeviceCache_whenPresent_shouldReturnHashPayload() {
        when(hashOps.entries("device:did:algo:ABC")).thenReturn(new HashMap<>(Map.of("status", "ACTIVE")));

        Optional<Map<String, String>> cache = service.getDeviceCache("did:algo:ABC");

        assertThat(cache).isPresent();
        assertThat(cache.get()).containsEntry("status", "ACTIVE");
    }

    @Test
    void getDeviceCache_whenAbsent_shouldReturnEmpty() {
        when(hashOps.entries("device:did:algo:ABC")).thenReturn(new HashMap<>());
        assertThat(service.getDeviceCache("did:algo:ABC")).isEmpty();
    }

    @Test
    void saveDeviceCache_shouldStoreExpectedFields() {
        service.saveDeviceCache("did:algo:ABC", "PUBLIC_KEY", List.of("read", "write"), 300);

        verify(hashOps).putAll(eq("device:did:algo:ABC"), any(Map.class));
        verify(redisTemplate).expire("device:did:algo:ABC", Duration.ofSeconds(300));
    }

    @Test
    void deleteDeviceCache_shouldDeleteKey() {
        service.deleteDeviceCache("did:algo:ABC");
        verify(redisTemplate).delete("device:did:algo:ABC");
    }

    // ── VP replay prevention ─────────────────────────────────────────────────

    @Test
    void markVpUsed_shouldSetKeyWithOneHourTtl() {
        service.markVpUsed("hash-abc");
        verify(valueOps).set("vp_used:hash-abc", "used", Duration.ofHours(1));
    }

    @Test
    void isVpUsed_whenPresent_shouldReturnTrue() {
        when(redisTemplate.hasKey("vp_used:hash-abc")).thenReturn(true);
        assertThat(service.isVpUsed("hash-abc")).isTrue();
    }

    @Test
    void isVpUsed_whenAbsent_shouldReturnFalse() {
        when(redisTemplate.hasKey("vp_used:hash-abc")).thenReturn(false);
        assertThat(service.isVpUsed("hash-abc")).isFalse();
    }

    // ── Failure tracking ─────────────────────────────────────────────────────

    @Test
    void incrementFailures_shouldReturnIncrementedCount() {
        when(valueOps.increment("failures:did:algo:ABC:" + FailureCategory.CHALLENGE)).thenReturn(3L);

        long count = service.incrementFailures("did:algo:ABC", FailureCategory.CHALLENGE, 600L);

        assertThat(count).isEqualTo(3L);
        verify(redisTemplate).expire("failures:did:algo:ABC:" + FailureCategory.CHALLENGE, Duration.ofSeconds(600L));
    }

    @Test
    void resetFailures_shouldDeleteKey() {
        service.resetFailures("did:algo:ABC", FailureCategory.CHALLENGE);
        verify(redisTemplate).delete("failures:did:algo:ABC:" + FailureCategory.CHALLENGE);
    }

    // ── JWT blacklist (admin) ─────────────────────────────────────────────────

    @Test
    void blacklistJwtToken_shouldSetKeyWithTtl() {
        service.blacklistJwtToken("jti-xyz", 3600L);
        verify(valueOps).set("jwt_blacklist:jti-xyz", "blacklisted", Duration.ofSeconds(3600L));
    }

    @Test
    void isJwtBlacklisted_whenPresent_shouldReturnTrue() {
        when(redisTemplate.hasKey("jwt_blacklist:jti-xyz")).thenReturn(true);
        assertThat(service.isJwtBlacklisted("jti-xyz")).isTrue();
    }

    // ── Device JWT PoP blacklist (tâche 2) ───────────────────────────────────

    @Test
    void saveLastDeviceJti_shouldPersistWithTtl() {
        service.saveLastDeviceJti("did:algo:ABC", "jti-123", 3600L);
        verify(valueOps).set("last_jti:did:algo:ABC", "jti-123", Duration.ofSeconds(3600L));
    }

    @Test
    void getLastDeviceJti_shouldReturnStoredJti() {
        when(valueOps.get("last_jti:did:algo:ABC")).thenReturn("jti-123");
        assertThat(service.getLastDeviceJti("did:algo:ABC")).isEqualTo("jti-123");
    }

    @Test
    void blacklistLastDeviceJwt_whenJtiPresent_shouldBlacklistAndKeepLastJtiKey() {
        when(valueOps.get("last_jti:did:algo:ABC")).thenReturn("jti-123");

        service.blacklistLastDeviceJwt("did:algo:ABC", 3600L);

        verify(valueOps).set("jwt_blacklist:jti-123", "blacklisted", Duration.ofSeconds(3600L));
    }

    @Test
    void clearDeviceAuthState_shouldRemoveSuspendedJwtBlacklistAndAuthKeys() {
        when(valueOps.get("last_jti:did:algo:ABC")).thenReturn("jti-123");

        service.clearDeviceAuthState("did:algo:ABC");

        verify(redisTemplate).delete("nonce:did:algo:ABC");
        verify(redisTemplate).delete("device:did:algo:ABC");
        verify(redisTemplate).delete("jwt_blacklist:jti-123");
        verify(redisTemplate).delete("last_jti:did:algo:ABC");
        verify(redisTemplate).delete("vp_used:did:did:algo:ABC");
    }

    @Test
    void blacklistLastDeviceJwt_whenNoJtiPresent_shouldDoNothing() {
        when(valueOps.get("last_jti:did:algo:ABC")).thenReturn(null);

        service.blacklistLastDeviceJwt("did:algo:ABC", 3600L);

        verify(valueOps, never()).set(eq("jwt_blacklist:any"), any(), any(Duration.class));
    }

    @Test
    void isDeviceJtiBlacklisted_shouldDelegateToJwtBlacklist() {
        when(redisTemplate.hasKey("jwt_blacklist:jti-789")).thenReturn(true);
        assertThat(service.isDeviceJtiBlacklisted("jti-789")).isTrue();
    }
}
