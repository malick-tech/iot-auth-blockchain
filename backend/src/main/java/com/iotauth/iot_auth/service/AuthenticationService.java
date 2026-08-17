package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.dto.request.VPRequest;
import com.iotauth.iot_auth.dto.response.ChallengeResponse;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.exception.DeviceNotFoundException;
import com.iotauth.iot_auth.exception.DeviceRevokedException;
import com.iotauth.iot_auth.exception.DeviceSuspendedException;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.exception.InvalidSignatureException;
import com.iotauth.iot_auth.exception.NonceExpiredException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.repository.VcRepository;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import com.iotauth.iot_auth.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final DeviceRepository deviceRepository;
    private final VcRepository vcRepository;
    private final JwtService jwtService;
    private final VpVerificationService vpVerificationService;
    private final RedisService redisService;
    private final AuditLogService auditLogService;
    private final AnomalyDetectionService anomalyService;
    private final AlgorandService algorandService;
    private final VcService vcService;

    @Value("${iot.auth.nonce-ttl-seconds:60}")
    private long nonceTtl;
    /**
     * Authenticates a device by validating its Verifiable Presentation (VP).
     *
     * Authentication flow:
     * 1. Retrieve device by DID
     * 2. Verify device status (not SUSPENDED, not REVOKED)
     * 3. Verify VP signature and credential
     * 4. Verify credential expiration
     * 5. Check if VP is cached/already used (replay prevention)
     * 6. Perform anomaly detection on authentication pattern
     * 7. Update device lastSeenAt timestamp
     * 8. Generate and return JWT PoP token
     * 9. Log successful authentication
     *
     * @param request VPRequest containing device DID and signed presentation
     * @return JwtPopResponse with JWT PoP token
     * @throws DeviceNotFoundException if device DID not found
     * @throws DeviceSuspendedException if device is suspended
     * @throws DeviceRevokedException if device is revoked
     * @throws InvalidSignatureException if VP signature is invalid
     */
    @Transactional
    public JwtPopResponse authenticateDevice(VPRequest request) {
        log.info("Starting authentication for DID: {}", request.getDid());

        // 1. Retrieve device by DID
        Device device = deviceRepository.findByDid(request.getDid())
                .orElseThrow(() -> {
                    log.warn("Device not found for DID: {}", request.getDid());
                    auditAuthenticationRejected(request.getDid(), "Device not found");
                    return DeviceNotFoundException.byDid(request.getDid());
                });

        // 2. Verify device status - NOT SUSPENDED
        if (device.getStatus() == DeviceStatus.SUSPENDED) {
            log.warn("Authentication attempt on suspended device: {}", device.getSerialNumber());
            auditAuthenticationRejected(request.getDid(), "Device is suspended");
            throw new DeviceSuspendedException(
                    "Device is suspended. Reason: " + device.getSuspensionReason()
            );
        }

       // 2. Verify device status - NOT REVOKED
        if (device.getStatus() == DeviceStatus.REVOKED) {
            log.warn("Authentication attempt on revoked device: {}", device.getSerialNumber());
            // Événement distinct et prioritaire pour un SOC : une tentative sur un DID
            // révoqué peut indiquer une clé compromise réutilisée après révocation.
            auditRevokedDeviceAttempt(request.getDid(), "Tentative d'authentification sur DID révoqué");
            throw new DeviceRevokedException(
                    "Device is revoked. Reason: " + device.getRevocationReason()
            );
        }

        // 2bis. Le renouvellement JWT n'est autorisé qu'aux dispositifs ACTIVE
        // (un dispositif PENDING ou PRE_REGISTERED n'a pas encore terminé l'enrôlement)
        if (device.getStatus() != DeviceStatus.ACTIVE) {
            log.warn("Authentication attempt on non-active device: {} - status={}",
                    device.getSerialNumber(), device.getStatus());
            auditAuthenticationRejected(request.getDid(), "Device is not ACTIVE (status=" + device.getStatus() + ")");
            throw InvalidDeviceStatusException.expected(DeviceStatus.ACTIVE, device.getStatus());
        }

        // 2ter. Consommer le nonce de fraîcheur émis par /api/auth/challenge/{did}
        String storedNonce = redisService.getNonce(request.getDid());
        if (storedNonce == null) {
            log.warn("Nonce absent ou expiré pour DID: {}", request.getDid());
            auditAuthenticationRejected(request.getDid(), "Nonce expired or not requested");
            throw new NonceExpiredException(request.getDid());
        }
        // Le nonce est à usage unique : on le supprime dès qu'il est lu,
        // qu'il corresponde ou non au challenge fourni.
        redisService.deleteNonce(request.getDid());

        if (!storedNonce.equals(request.getChallenge())) {
            log.warn("Challenge invalide pour DID: {}", request.getDid());
            anomalyService.recordChallengeFailure(request.getDid());
            auditAuthenticationRejected(request.getDid(), "Challenge does not match issued nonce");
            throw new InvalidSignatureException("Challenge invalide ou expiré");
        }

        // 3. Verify VP signature using device's public key (signature over challenge + VP)
        boolean vpValid = vpVerificationService.verifyPresentation(
                request.getVerifiablePresentation(),
                request.getChallenge(),
                request.getSignature(),
                device.getPublicKey()
        );

        if (!vpValid) {
            log.warn("Invalid VP signature for DID: {}", request.getDid());
            // Déclencheur 2 (spécifique) : signature de VP invalide, distinct
            // du déclencheur 1 qui couvre les échecs du protocole challenge-response.
            anomalyService.recordVpFailure(request.getDid());
            auditAuthenticationRejected(request.getDid(), "Invalid VP signature");
            throw new InvalidSignatureException("VP signature verification failed");
        }

        // 4. Extract credential from VP and verify it
        String vcId = vpVerificationService.extractVcIdFromPresentation(
                request.getVerifiablePresentation()
        );

        VerifiableCredential vc = vcRepository.findByVcId(vcId)
                .orElseThrow(() -> {
                    log.warn("Credential not found: {}", vcId);
                    auditAuthenticationRejected(request.getDid(), "Credential not found: " + vcId);
                    return new InvalidSignatureException("Credential not found in presentation");
                });

        // 4bis. Verify(Kpub_admin, VC) - signature de l'Issuer sur le VC
        if (!vcService.verifyIssuerSignature(vc.getRawCredential())) {
            log.warn("Invalid issuer signature on VC: {} for DID: {}", vcId, request.getDid());
            auditAuthenticationRejected(request.getDid(), "Invalid issuer signature on VC");
            throw new InvalidSignatureException("VC issuer signature verification failed");
        }

        // 5. Verify credential expiration
        LocalDateTime now = LocalDateTime.now();
        if (vc.getExpirationDate().isBefore(now)) {
            log.warn("Credential expired for DID: {} - Expiration: {}", request.getDid(), vc.getExpirationDate());
            auditAuthenticationRejected(request.getDid(), "Credential expired");
            throw new InvalidSignatureException("Credential has expired");
        }

        // 5bis. Résolution on-chain du statut - confirme ACTIVE sur Algorand,
        // en complément (pas en remplacement) du statut PostgreSQL déjà vérifié.
        Optional<byte[]> onChainStatusBox = algorandService.readBox("st:", request.getDid());
        if (onChainStatusBox.isEmpty()) {
            log.warn("DID introuvable on-chain: {}", request.getDid());
            auditAuthenticationRejected(request.getDid(), "DID not found on-chain");
            throw new InvalidSignatureException("DID not resolvable on-chain");
        }
        String onChainStatus = new String(onChainStatusBox.get(), StandardCharsets.UTF_8);
        if (!"ACTIVE".equals(onChainStatus)) {
            log.warn("DID non ACTIVE on-chain ({}): {}", onChainStatus, request.getDid());
            auditAuthenticationRejected(request.getDid(), "DID not ACTIVE on-chain: " + onChainStatus);
            throw new InvalidSignatureException("DID not ACTIVE on-chain");
        }

        // 6. Check replay: verify VP not already cached
        String vpHash = CryptoUtils.hashVp(request.getVerifiablePresentation());
        if (redisService.isVpUsed(vpHash)) {
            log.warn("Replay attack detected - VP already used: {} for DID: {}", vpHash, request.getDid());
            anomalyService.recordChallengeFailure(request.getDid());
            auditAuthenticationRejected(request.getDid(), "Replay attack - VP already used");
            throw new InvalidSignatureException("VP has already been used (replay prevention)");
        }

        // 7. Mark VP as used in Redis
        redisService.markVpUsed(vpHash);

        // 8. Perform anomaly detection
        long failureCount = anomalyService.getChallengeFailures(request.getDid());
        if (failureCount > 5) {
            log.warn("High anomaly score for DID: {} - Failure count: {}", request.getDid(), failureCount);
            auditAnomalyDetected(request.getDid(), "High failure rate: " + failureCount);
            // Note: In production, could auto-suspend device if score too high
        }

        // Reset failure count on successful auth
        anomalyService.resetChallengeFailures(request.getDid());

        // 9. Update device lastSeenAt
        device.setLastSeenAt(now);
        deviceRepository.save(device);

        // 10. Generate JWT PoP token with device public key
        JwtPopResponse jwtPopResponse = jwtService.generateJwtPop(device.getDid(), device.getPublicKey());
        jwtPopResponse.setTokenType("Bearer");
        jwtPopResponse.setPermissions(vc.getPermissions());
        jwtPopResponse.setCredentialId(vc.getVcId());
        jwtPopResponse.setVerifiableCredential(vc.getRawCredential());
        jwtPopResponse.setDeviceSerialNumber(device.getSerialNumber());

        // 11. Log successful authentication
        auditAuthenticationSuccess(request.getDid());
        auditLogService.record(
                EventType.JWT_RENEWED,
                request.getDid(),
                ActorType.DEVICE,
                true,
                "JWT PoP renouvelé, credentialId=" + vc.getVcId()
        );

        log.info("Authentication successful for DID: {}", request.getDid());

        return jwtPopResponse;
    }

    /**
     * Émet un nonce de fraîcheur (challenge) pour le renouvellement du JWT PoP.
     * Le dispositif doit signer (challenge || VP) avec sa clé privée et soumettre
     * le résultat à /api/auth/authenticate dans le délai imparti (TTL Redis).
     *
     * @param did DID du dispositif demandant le renouvellement
     * @return challenge à inclure dans la VPRequest
     * @throws DeviceNotFoundException si le DID est inconnu
     */
   /**
     * Émet un nonce de fraîcheur (challenge) pour le renouvellement du JWT PoP.
     */
    public ChallengeResponse issueRenewalChallenge(String did) {
        Device device = deviceRepository.findByDid(did)
                .orElseThrow(() -> DeviceNotFoundException.byDid(did));

        if (device.getStatus() != DeviceStatus.ACTIVE) {
            throw InvalidDeviceStatusException.expected(DeviceStatus.ACTIVE, device.getStatus());
        }

        String nonce = CryptoUtils.generateNonce();
        redisService.saveNonce(did, nonce, nonceTtl);

        log.info("Challenge de renouvellement émis pour DID: {}", did);
        auditLogService.record(
                EventType.VP_CHALLENGE_ISSUED,
                did,
                ActorType.DEVICE,
                true,
                "Nonce de renouvellement émis (TTL " + nonceTtl + "s)"
        );

        return ChallengeResponse.builder()
                .nonce(nonce)
                .did(did)
                .expiresIn(nonceTtl)
                .build();
    }

    /**
     * Validates if a device is currently authorized (active + not suspended).
     *
     * @param did Device DID
     * @return true if device can authenticate
     */
    public boolean isDeviceAuthorized(String did) {
        return deviceRepository.findByDid(did)
                .filter(device -> device.getStatus() == DeviceStatus.ACTIVE)
                .isPresent();
    }

    /**
     * Checks if device has specific permission.
     *
     * @param did Device DID
     * @param permission Permission to check (e.g., "read", "write")
     * @return true if device has permission
     */
    public boolean hasDevicePermission(String did, String permission) {
    return deviceRepository.findByDid(did)
            .map(device -> vcRepository.findBySubjectDid(did)
                    .stream()
                    .anyMatch(vc -> vc.getPermissions().contains(permission)))
            .orElse(false);
}

    // ============= Audit Helpers =============

    private void auditAuthenticationSuccess(String did) {
        auditLogService.record(
                EventType.AUTHENTICATION_SUCCESS,
                did,
                ActorType.DEVICE,
                true,
                "Authentication successful"
        );
    }

    private void auditAuthenticationRejected(String did, String reason) {
        auditLogService.record(
                EventType.AUTHENTICATION_FAILURE,
                did,
                ActorType.DEVICE,
                false,
                "Authentication rejected: " + reason
        );
    }

    private void auditAnomalyDetected(String did, String anomaly) {
        auditLogService.record(
                EventType.ANOMALY_DETECTED,
                did,
                ActorType.DEVICE,
                false,
                "Anomaly detected: " + anomaly
        );
    }

    private void auditRevokedDeviceAttempt(String did, String details) {
        auditLogService.record(
                EventType.REVOKED_DEVICE_ACCESS_ATTEMPT,
                did,
                ActorType.DEVICE,
                false,
                details
        );
    }
}
