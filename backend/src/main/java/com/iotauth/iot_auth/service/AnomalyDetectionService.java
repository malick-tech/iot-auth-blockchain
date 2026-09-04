package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.enums.FailureCategory;
import com.iotauth.iot_auth.dto.request.RevocationRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Détecte les comportements anormaux des dispositifs (échecs répétés de
 * challenge-response, de vérification VP, violations de permissions) et
 * déclenche une suspension automatique quand les seuils configurés sont
 * atteints.
 *
 * Dépendances intentionnellement minimales : ce service ne connaît que
 * RedisService (compteurs) et DeviceSuspensionPort (abstraction de suspension).
 * Il n'a pas de dépendance directe sur RevocationService, ce qui évite le
 * cycle de dépendances circulaire AnomalyDetectionService ↔ RevocationService.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnomalyDetectionService {

    private final RedisService redisService;

    /**
     * Port de suspension : RevocationService l'implémente.
     * L'injection passe par l'interface, pas par le bean concret,
     * ce qui rompt le cycle de dépendances.
     */
    private final DeviceSuspensionPort suspensionPort;

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
        long count = redisService.incrementFailures(did, FailureCategory.CHALLENGE, challengeTtlSeconds);
        log.warn("Echec challenge-response pour did={} - compteur={}", did, count);
        if (count >= challengeThreshold) {
            triggerSuspension(did, FailureCategory.CHALLENGE, count);
        }
    }

    public void recordVpFailure(String did) {
        long count = redisService.incrementFailures(did, FailureCategory.VP, vpTtlSeconds);
        log.warn("Echec verification VP pour did={} - compteur={}", did, count);
        if (count >= vpThreshold) {
            triggerSuspension(did, FailureCategory.VP, count);
        }
    }

    public void recordPermissionViolation(String did) {
        long count = redisService.incrementFailures(did, FailureCategory.PERMISSION, permTtlSeconds);
        log.warn("Violation de permissions pour did={} - compteur={}", did, count);
        if (count >= permThreshold) {
            triggerSuspension(did, FailureCategory.PERMISSION, count);
        }
    }

    public long getChallengeFailures(String did) {
        return redisService.getFailures(did, FailureCategory.CHALLENGE);
    }

    public void resetChallengeFailures(String did) {
        redisService.resetFailures(did, FailureCategory.CHALLENGE);
    }

    private void triggerSuspension(String did, String reason, long count) {
        try {
            RevocationRequest request = new RevocationRequest();
            request.setReason("Suspension automatique - anomalie '" + reason + "' (" + count + " occurrence(s))");
            suspensionPort.suspendDevice(did, request);
            // Réinitialise les compteurs uniquement si la suspension a réussi.
            // Si le dispositif est déjà suspendu/révoqué, on ne remet pas à zéro
            // afin de conserver la traçabilité des tentatives suspectes.
            redisService.resetFailures(did, reason);
        } catch (Exception e) {
            log.warn("Suspension automatique impossible pour did={} (reason={}) : {}", did, reason, e.getMessage());
        }
    }
}
