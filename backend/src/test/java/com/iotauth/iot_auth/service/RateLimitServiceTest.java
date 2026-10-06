package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.exception.RateLimitExceededException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RateLimitServiceTest {

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> valueOps;
    private RateLimitService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        service = new RateLimitService(redisTemplate);
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "maxRequests", 20L);
        ReflectionTestUtils.setField(service, "ipMaxRequests", 600L);
        ReflectionTestUtils.setField(service, "windowSeconds", 60L);
        ReflectionTestUtils.setField(service, "adminLoginMaxRequests", 5L);
        ReflectionTestUtils.setField(service, "adminLoginWindowSeconds", 60L);
    }

    @Test
    void requireAllowed_whenUnderQuota_shouldNotThrow() {
        when(valueOps.increment("ratelimit:did-auth:did:algo:A|10.0.0.5")).thenReturn(20L);

        assertThatCode(() -> service.requireAllowed("auth", "did:algo:A", "10.0.0.5"))
                .doesNotThrowAnyException();
    }

    @Test
    void requireAllowed_whenOverQuota_shouldThrowRateLimitExceeded() {
        when(valueOps.increment("ratelimit:did-auth:did:algo:A|10.0.0.5")).thenReturn(21L);

        assertThatThrownBy(() -> service.requireAllowed("auth", "did:algo:A", "10.0.0.5"))
                .isInstanceOf(RateLimitExceededException.class);
    }

    @Test
    void requireAllowed_countsPerSourceIp_soAnotherCallerCannotExhaustTheQuota() {
        // Un attaquant (203.0.113.9) a épuisé SON quota pour ce DID...
        when(valueOps.increment("ratelimit:did-challenge:did:algo:VICTIM|203.0.113.9")).thenReturn(500L);
        // ... mais le compteur du dispositif légitime (via la gateway) est distinct.
        when(valueOps.increment("ratelimit:did-challenge:did:algo:VICTIM|172.18.0.3")).thenReturn(1L);

        assertThatThrownBy(() -> service.requireAllowed("challenge", "did:algo:VICTIM", "203.0.113.9"))
                .isInstanceOf(RateLimitExceededException.class);
        assertThatCode(() -> service.requireAllowed("challenge", "did:algo:VICTIM", "172.18.0.3"))
                .doesNotThrowAnyException();
    }

    @Test
    void requireAllowed_withBlankDid_shouldBeNoOp() {
        service.requireAllowed("auth", " ", "10.0.0.5");
        service.requireAllowed("auth", null, "10.0.0.5");

        verify(valueOps, never()).increment(anyString());
    }

    @Test
    void requireAllowed_whenDisabled_shouldNotTouchRedis() {
        ReflectionTestUtils.setField(service, "enabled", false);

        assertThatCode(() -> service.requireAllowed("auth", "did:algo:A", "10.0.0.5"))
                .doesNotThrowAnyException();
        verify(valueOps, never()).increment(anyString());
    }

    @Test
    void isAllowed_fromTrustedProxy_usesTheLargeIpCeiling() {
        when(valueOps.increment("ratelimit:operational:172.18.0.3")).thenReturn(600L);

        assertThat(service.isAllowed("operational", "172.18.0.3", true)).isTrue();

        when(valueOps.increment("ratelimit:operational:172.18.0.3")).thenReturn(601L);
        assertThat(service.isAllowed("operational", "172.18.0.3", true)).isFalse();
    }

    @Test
    void isAllowed_fromDirectClient_keepsTheStrictQuota() {
        when(valueOps.increment("ratelimit:enrollment:203.0.113.9")).thenReturn(20L);
        assertThat(service.isAllowed("enrollment", "203.0.113.9", false)).isTrue();

        when(valueOps.increment("ratelimit:enrollment:203.0.113.9")).thenReturn(21L);
        assertThat(service.isAllowed("enrollment", "203.0.113.9", false)).isFalse();
    }

    @Test
    void isAllowed_adminLogin_isAlwaysStrict_evenFromTrustedProxy() {
        when(valueOps.increment("ratelimit:admin-login:127.0.0.1")).thenReturn(6L);

        assertThat(service.isAllowed("admin-login", "127.0.0.1", true)).isFalse();
    }
}
