package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.enums.FailureCategory;
import com.iotauth.iot_auth.dto.request.RevocationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnomalyDetectionServiceTest {

    @Mock private RedisService redisService;

    /**
     * On mocke l'interface DeviceSuspensionPort, pas RevocationService directement.
     * Cela reflète le vrai graphe de dépendances et valide que le découplage est correct.
     */
    @Mock private DeviceSuspensionPort suspensionPort;

    private AnomalyDetectionService service;

    private static final String DID = "did:algo:DEVICE";

    @BeforeEach
    void setUp() {
        service = new AnomalyDetectionService(redisService, suspensionPort);
        ReflectionTestUtils.setField(service, "challengeTtlSeconds", 600L);
        ReflectionTestUtils.setField(service, "challengeThreshold", 5L);
        ReflectionTestUtils.setField(service, "vpTtlSeconds", 300L);
        ReflectionTestUtils.setField(service, "vpThreshold", 3L);
        ReflectionTestUtils.setField(service, "permTtlSeconds", 3600L);
        ReflectionTestUtils.setField(service, "permThreshold", 1L);
    }

    // ── recordChallengeFailure ───────────────────────────────────────────────

    @Test
    void recordChallengeFailure_belowThreshold_shouldNotTriggerSuspension() {
        when(redisService.incrementFailures(DID, FailureCategory.CHALLENGE, 600L)).thenReturn(3L);

        service.recordChallengeFailure(DID);

        verify(redisService).incrementFailures(DID, FailureCategory.CHALLENGE, 600L);
        verify(suspensionPort, never()).suspendDevice(any(), any());
    }

    @Test
    void recordChallengeFailure_atThreshold_shouldTriggerSuspension() {
        when(redisService.incrementFailures(DID, FailureCategory.CHALLENGE, 600L)).thenReturn(5L);

        service.recordChallengeFailure(DID);

        verify(suspensionPort).suspendDevice(eq(DID), any(RevocationRequest.class));
    }

    @Test
    void recordChallengeFailure_aboveThreshold_shouldTriggerSuspension() {
        when(redisService.incrementFailures(DID, FailureCategory.CHALLENGE, 600L)).thenReturn(7L);

        service.recordChallengeFailure(DID);

        verify(suspensionPort).suspendDevice(eq(DID), any(RevocationRequest.class));
    }

    // ── recordVpFailure ──────────────────────────────────────────────────────

    @Test
    void recordVpFailure_belowThreshold_shouldNotTriggerSuspension() {
        when(redisService.incrementFailures(DID, FailureCategory.VP, 300L)).thenReturn(2L);

        service.recordVpFailure(DID);

        verify(redisService).incrementFailures(DID, FailureCategory.VP, 300L);
        verify(suspensionPort, never()).suspendDevice(any(), any());
    }

    @Test
    void recordVpFailure_atThreshold_shouldTriggerSuspension() {
        when(redisService.incrementFailures(DID, FailureCategory.VP, 300L)).thenReturn(3L);

        service.recordVpFailure(DID);

        verify(suspensionPort).suspendDevice(eq(DID), any(RevocationRequest.class));
    }

    // ── recordPermissionViolation ────────────────────────────────────────────

    @Test
    void recordPermissionViolation_firstOccurrence_shouldTriggerImmediateSuspension() {
        when(redisService.incrementFailures(DID, FailureCategory.PERMISSION, 3600L)).thenReturn(1L);

        service.recordPermissionViolation(DID);

        // Seuil = 1 : la première violation doit déclencher la suspension immédiate
        verify(suspensionPort).suspendDevice(eq(DID), any(RevocationRequest.class));
    }

    // ── getChallengeFailures / resetChallengeFailures ────────────────────────

    @Test
    void getChallengeFailures_shouldDelegateToRedisService() {
        when(redisService.getFailures(DID, FailureCategory.CHALLENGE)).thenReturn(3L);

        long count = service.getChallengeFailures(DID);

        verify(redisService).getFailures(DID, FailureCategory.CHALLENGE);
        assert count == 3L;
    }

    @Test
    void resetChallengeFailures_shouldDeleteCounterInRedis() {
        service.resetChallengeFailures(DID);

        verify(redisService).resetFailures(DID, FailureCategory.CHALLENGE);
    }

    // ── suspension déjà active (idempotence) ────────────────────────────────

    @Test
    void recordChallengeFailure_whenAlreadySuspended_suspensionErrorShouldNotPropagate() {
        when(redisService.incrementFailures(DID, FailureCategory.CHALLENGE, 600L)).thenReturn(5L);
        org.mockito.Mockito.doThrow(new RuntimeException("Already suspended"))
                .when(suspensionPort).suspendDevice(eq(DID), any());

        org.assertj.core.api.Assertions.assertThatCode(() -> service.recordChallengeFailure(DID))
                .doesNotThrowAnyException();
    }
}
