package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.AlgorandBoxPrefix;
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
     * Authentifie un dispositif en validant sa Verifiable Presentation (VP).
     *
     * Flux d'authentification :
     * 1. Récupérer le dispositif par DID
     * 2. Vérifier le statut du dispositif (pas SUSPENDED, pas REVOKED)
     * 3. Vérifier la signature VP et le credential
     * 4. Vérifier l'expiration du credential
     * 5. Contrôler le replay (VP déjà utilisée)
     * 6. Détection d'anomalies
     * 7. Mettre à jour lastSeenAt
     * 8. Générer et retourner le JWT PoP
     * 9. Journaliser l'authentification réussie
     *
     * @param request VPRequest contenant le DID du dispositif et la présentation signée
     * @return JwtPopResponse avec le JWT PoP
     * @throws DeviceNotFoundException   si le DID est inconnu
     * @throws DeviceSuspendedException  si le dispositif est suspendu
     * @throws DeviceRevokedException    si le dispositif est révoqué
     * @throws InvalidSignatureException si la signature VP est invalide
     */
    @Transactional
    public JwtPopResponse authenticateDevice(VPRequest request) {
        log.info("Démarrage de l'authentification pour DID: {}", request.getDid());

        // 1. Récupérer le dispositif par DID
        Device device = deviceRepository.findByDid(request.getDid())
                .orElseThrow(() -> {
                    log.warn("Dispositif introuvable pour DID: {}", request.getDid());
                    auditAuthenticationRejected(request.getDid(), "Device not found");
                    return DeviceNotFoundException.byDid(request.getDid());
                });

        // 2. Vérifier le statut - PAS SUSPENDU
        if (device.getStatus() == DeviceStatus.SUSPENDED) {
            log.warn("Tentative d'authentification sur dispositif suspendu: {}", device.getSerialNumber());
            auditAuthenticationRejected(request.getDid(), "Device is suspended");
            throw new DeviceSuspendedException(
                    "Device is suspended. Reason: " + device.getSuspensionReason()
            );
        }

        // 2. Vérifier le statut - PAS RÉVOQUÉ
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
            log.warn("Tentative d'authentification sur dispositif non-actif: {} - statut={}",
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

        // 3. Vérifier la signature VP avec la clé publique du dispositif (signature sur challenge + VP)
        boolean vpValid = vpVerificationService.verifyPresentation(
                request.getVerifiablePresentation(),
                request.getChallenge(),
                request.getSignature(),
                device.getPublicKey()
        );

        if (!vpValid) {
            log.warn("Signature VP invalide pour DID: {}", request.getDid());
            // Déclencheur 2 (spécifique) : signature de VP invalide, distinct
            // du déclencheur 1 qui couvre les échecs du protocole challenge-response.
            anomalyService.recordVpFailure(request.getDid());
            auditAuthenticationRejected(request.getDid(), "Invalid VP signature");
            throw new InvalidSignatureException("VP signature verification failed");
        }

        // 4. Extraire le credential de la VP et le vérifier
        String vcId = vpVerificationService.extractVcIdFromPresentation(
                request.getVerifiablePresentation()
        );

        VerifiableCredential vc = vcRepository.findByVcId(vcId)
                .orElseThrow(() -> {
                    log.warn("Credential introuvable: {}", vcId);
                    auditAuthenticationRejected(request.getDid(), "Credential not found: " + vcId);
                    return new InvalidSignatureException("Credential not found in presentation");
                });

        // 4bis. Verify(Kpub_admin, VC) - signature de l'Issuer sur le VC
        if (!vcService.verifyIssuerSignature(vc.getRawCredential())) {
            log.warn("Signature issuer invalide sur VC: {} pour DID: {}", vcId, request.getDid());
            auditAuthenticationRejected(request.getDid(), "Invalid issuer signature on VC");
            throw new InvalidSignatureException("VC issuer signature verification failed");
        }

        // 5. Vérifier l'expiration du credential
        LocalDateTime now = LocalDateTime.now();
        if (vc.getExpirationDate().isBefore(now)) {
            log.warn("Credential expiré pour DID: {} - Expiration: {}", request.getDid(), vc.getExpirationDate());
            auditAuthenticationRejected(request.getDid(), "Credential expired");
            throw new InvalidSignatureException("Credential has expired");
        }

        // 5bis. Résolution on-chain du statut - confirme ACTIVE sur Algorand,
        // en complément (pas en remplacement) du statut PostgreSQL déjà vérifié.
        Optional<byte[]> onChainStatusBox = algorandService.readBox(AlgorandBoxPrefix.STATUS, request.getDid());
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

        // 6. Contrôler le replay : vérifier que la VP n'a pas déjà été utilisée
        String vpHash = CryptoUtils.hashVp(request.getVerifiablePresentation());
        if (redisService.isVpUsed(vpHash)) {
            log.warn("Attaque par rejeu détectée - VP déjà utilisée: {} pour DID: {}", vpHash, request.getDid());
            anomalyService.recordChallengeFailure(request.getDid());
            auditAuthenticationRejected(request.getDid(), "Replay attack - VP already used");
            throw new InvalidSignatureException("VP has already been used (replay prevention)");
        }

        // 7. Marquer la VP comme utilisée dans Redis
        redisService.markVpUsed(vpHash);

        // 8. Détection d'anomalies
        long failureCount = anomalyService.getChallengeFailures(request.getDid());
        if (failureCount > 5) {
            log.warn("Score d'anomalie élevé pour DID: {} - Compteur d'échecs: {}", request.getDid(), failureCount);
            auditAnomalyDetected(request.getDid(), "High failure rate: " + failureCount);
            // En production, possibilité de suspendre automatiquement si le score dépasse le seuil
        }

        // Réinitialiser le compteur d'échecs après authentification réussie
        anomalyService.resetChallengeFailures(request.getDid());

        // 9. Mettre à jour lastSeenAt
        device.setLastSeenAt(now);
        deviceRepository.save(device);

        // 10. Générer le JWT PoP avec la clé publique du dispositif
        JwtPopResponse jwtPopResponse = jwtService.generateJwtPop(device.getDid(), device.getPublicKey());
        jwtPopResponse.setTokenType("Bearer");
        jwtPopResponse.setPermissions(vc.getPermissions());
        jwtPopResponse.setCredentialId(vc.getVcId());
        jwtPopResponse.setVerifiableCredential(vc.getRawCredential());
        jwtPopResponse.setDeviceSerialNumber(device.getSerialNumber());

        // 11. Journaliser l'authentification réussie
        auditAuthenticationSuccess(request.getDid());
        auditLogService.record(
                EventType.JWT_RENEWED,
                request.getDid(),
                ActorType.DEVICE,
                true,
                "JWT PoP renouvelé, credentialId=" + vc.getVcId()
        );

        log.info("Authentification réussie pour DID: {}", request.getDid());

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
     * Vérifie si un dispositif est actuellement autorisé (actif, non suspendu).
     *
     * @param did DID du dispositif
     * @return true si le dispositif peut s'authentifier
     */
    public boolean isDeviceAuthorized(String did) {
        return deviceRepository.findByDid(did)
                .filter(device -> device.getStatus() == DeviceStatus.ACTIVE)
                .isPresent();
    }

    /**
     * Vérifie si un dispositif possède une permission spécifique.
     *
     * @param did        DID du dispositif
     * @param permission Permission à vérifier (ex: "device:read", "device:operate")
     * @return true si le dispositif possède la permission
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
                "Authentification réussie"
        );
    }

    private void auditAuthenticationRejected(String did, String reason) {
        auditLogService.record(
                EventType.AUTHENTICATION_FAILURE,
                did,
                ActorType.DEVICE,
                false,
                "Authentification refusée : " + reason
        );
    }

    private void auditAnomalyDetected(String did, String anomaly) {
        auditLogService.record(
                EventType.ANOMALY_DETECTED,
                did,
                ActorType.DEVICE,
                false,
                "Anomalie détectée : " + anomaly
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
