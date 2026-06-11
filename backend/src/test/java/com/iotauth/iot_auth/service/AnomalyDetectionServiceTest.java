package com.iotauth.iot_auth.service;

import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AnomalyDetectionServiceTest {

    @Test
    void recordChallengeFailure_doesNotThrow() {
        RedisService redisService = mock(RedisService.class);
        AnomalyDetectionService service = new AnomalyDetectionService(redisService);

        service.recordChallengeFailure("did:algo:ABC");

        verify(redisService).incrementFailures("did:algo:ABC", "challenge", 0);
    }
}
