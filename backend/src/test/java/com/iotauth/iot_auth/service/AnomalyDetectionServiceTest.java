package com.iotauth.iot_auth.service;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AnomalyDetectionServiceTest {

    @Test
    void recordChallengeFailure_doesNotThrow() {
        RedisService redisService = mock(RedisService.class);
        RevocationService revocationService = mock(RevocationService.class);
        AnomalyDetectionService service = new AnomalyDetectionService(redisService, revocationService);
        ReflectionTestUtils.setField(service, "challengeTtlSeconds", 600L);
        ReflectionTestUtils.setField(service, "challengeThreshold", 5L);

        service.recordChallengeFailure("did:algo:ABC");

        verify(redisService).incrementFailures("did:algo:ABC", "challenge", 600L);
    }
}