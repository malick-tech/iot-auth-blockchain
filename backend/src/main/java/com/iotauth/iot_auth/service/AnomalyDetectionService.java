package com.iotauth.iot_auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AnomalyDetectionService {

    private final RedisService redisService;

    @Value("${iot.auth.failure-ttl-seconds:300}")
    private long failureTtlSeconds;

    public void recordChallengeFailure(String did) {
        redisService.incrementFailures(did, "challenge", failureTtlSeconds);
    }

    public long getChallengeFailures(String did) {
        return redisService.getFailures(did, "challenge");
    }

    public void resetChallengeFailures(String did) {
        redisService.resetFailures(did, "challenge");
    }
}
