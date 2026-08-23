package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.dto.request.RevocationRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AnomalyDetectionService {

    private final RedisService redisService;
    private final RevocationService revocationService;

    @Value("${iot.auth.failure-ttl-seconds-challenge:600}")
    private long challengeTtlSeconds;

    @Value("${iot.auth.failure-threshold-challenge:5}")
    private long challengeThreshold;

    @Value("${iot.auth.failure-ttl-seconds-vp:300}")
    private long vpTtlSeconds;

    @Value("${iot.auth.failure-threshold-vp:3}")
    private long vpThreshold;

    @Value("${iot.auth.failure-ttl-seconds-perm:3600}")
    private long permTtlSeconds;

    @Value("${iot.auth.failure-threshold-perm:1}")
    private long permThreshold;

    public void recordChallengeFailure(String did) {
        long count = redisService.incrementFailures(did, "challenge", challengeTtlSeconds);
        log.warn("Echec challenge-response pour did={} - compteur={}", did, count);
        if (count >= challengeThreshold) {
            triggerSuspension(did, "challenge", count);
        }
    }

    public void recordVpFailure(String did) {
        long count = redisService.incrementFailures(did, "vp", vpTtlSeconds);
        log.warn("Echec verification VP pour did={} - compteur={}", did, count);
        if (count >= vpThreshold) {
            triggerSuspension(did, "vp", count);
        }
    }

    public void recordPermissionViolation(String did) {
        long count = redisService.incrementFailures(did, "perm", permTtlSeconds);
        log.warn("Violation de permissions pour did={} - compteur={}", did, count);
        if (count >= permThreshold) {
            triggerSuspension(did, "perm", count);
        }
    }

    public long getChallengeFailures(String did) {
        return redisService.getFailures(did, "challenge");
    }

    public void resetChallengeFailures(String did) {
        redisService.resetFailures(did, "challenge");
    }

    private void triggerSuspension(String did, String reason, long count) {
        try {
            RevocationRequest request = new RevocationRequest();
            request.setReason("Suspension automatique - anomalie '" + reason + "' (" + count + " occurrence(s))");
            revocationService.suspendDevice(did, request);
            // Réinitialise les compteurs uniquement si la suspension a réussi.
            // Si le dispositif est déjà suspendu/révoqué, on ne remet pas à zéro
            // afin de conserver la traçabilité des tentatives suspectes.
            redisService.resetFailures(did, reason);
        } catch (Exception e) {
            log.warn("Suspension automatique impossible pour did={} (reason={}) : {}", did, reason, e.getMessage());
        }
    }
}