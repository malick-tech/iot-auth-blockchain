package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.dto.request.ChallengeResponseRequest;
import com.iotauth.iot_auth.dto.request.FirstContactRequest;
import com.iotauth.iot_auth.dto.response.ChallengeResponse;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.exception.*;
import com.iotauth.iot_auth.repository.AuthLogRepository;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class EnrollmentService {

    private final DeviceRepository  deviceRepository;
    private final AuthLogRepository authLogRepository;
    private final RedisService      redisService;
    private final AlgorandService   algorandService;
    private final JwtService        jwtService;
    private final VcService         vcService;
    private final AnomalyDetectionService anomalyService;

    @Value("${iot.auth.nonce-ttl-seconds:60}")
    private long nonceTtl;

    @Value("${iot.auth.redis-ttl-seconds:300}")
    private long redisTtl;

    private final SecureRandom secureRandom = new SecureRandom();

    // ════════════════════════════════════════════════════════════
    // ÉTAPE 1 — Premier contact (σ₀ = Sig(Kpriv, serial || DID))
    // ════════════════════════════════════════════════════════════

    @Transactional
    public ChallengeResponse handleFirstContact(FirstContactRequest request) {
        log.info("Premier contact — serial={}", request.getSerialNumber());

        // 1. Vérifier que le device est PENDING en base
        Device device = deviceRepository.findBySerialNumber(request.getSerialNumber())
                .orElseThrow(() -> DeviceNotFoundException.bySerial(request.getSerialNumber()));

        if (device.getStatus() != DeviceStatus.PENDING) {
            throw new InvalidDeviceStatusException(
                    "Premier contact refusé — statut actuel : " + device.getStatus()
                            + " (PENDING requis)");
        }

        // 2. Valider le format du DID : doit être "did:algo:" + publicKey
        if (!CryptoUtils.validateDidFormat(request.getDid(), request.getPublicKey())) {
            throw new InvalidSignatureException(
                    "DID incohérent avec la clé publique : " + request.getDid());
        }

        // 3. Vérifier σ₀ = Sig(Kpriv, serial || DID)
        //    Le device prouve qu'il possède la clé privée associée à Kpub
        String messageToVerify = request.getSerialNumber() + request.getDid();
        boolean sigmaZeroValid = CryptoUtils.verifyEd25519(
                request.getPublicKey(),
                messageToVerify,
                request.getSignature()
        );

        if (!sigmaZeroValid) {
            log.warn("σ₀ invalide pour serial={}", request.getSerialNumber());
            throw new InvalidSignatureException(
                    "Signature σ₀ invalide — vérification Ed25519 échouée");
        }

        // 4. Vérifier unicité du DID (un device ne peut pas usurper le DID d'un autre)
        if (deviceRepository.existsByDid(request.getDid())) {
            throw new DeviceAlreadyExistsException(
                    "Ce DID est déjà utilisé par un autre device : " + request.getDid());
        }

        // 5. Passer le device en PRE_REGISTERED et renseigner les champs cryptographiques
        device.setDid(request.getDid());
        device.setPublicKey(request.getPublicKey());
        device.setStatus(DeviceStatus.PRE_REGISTERED);
        deviceRepository.save(device);

        // 6. Générer le nonce challenge (32 octets aléatoires, TTL = 60s)
        String nonce = generateNonce();
        redisService.saveNonce(request.getDid(), nonce, nonceTtl);

        log.info("σ₀ valide — nonce émis pour did={}", request.getDid());

        return ChallengeResponse.builder()
                .nonce(nonce)
                .did(request.getDid())
                .expiresIn(nonceTtl)
                .build();
    }

    // ════════════════════════════════════════════════════════════
    // ÉTAPE 2 — Réponse au challenge (σ₁ = Sig(Kpriv, nonce))
    //           + Activation complète du device
    // ════════════════════════════════════════════════════════════

    @Transactional
    public JwtPopResponse handleChallengeResponse(ChallengeResponseRequest request) {
        log.info("Réponse au challenge — did={}", request.getDid());

        // 1. Récupérer le nonce depuis Redis AVANT tout (TTL = 60s)
        String nonce = redisService.getNonce(request.getDid());
        if (nonce == null) {
            throw new NonceExpiredException(request.getDid());
        }

        // 2. Supprimer immédiatement le nonce → non-rejouabilité garantie
        //    (même si la suite échoue, le nonce ne peut plus être réutilisé)
        redisService.deleteNonce(request.getDid());

        // 3. Récupérer le device
        Device device = deviceRepository.findByDid(request.getDid())
                .orElseThrow(() -> DeviceNotFoundException.byDid(request.getDid()));

        if (device.getStatus() != DeviceStatus.PRE_REGISTERED) {
            throw new InvalidDeviceStatusException(
                    "Challenge refusé — statut actuel : " + device.getStatus()
                            + " (PRE_REGISTERED requis)");
        }

        // 4. Vérifier σ₁ = Sig(Kpriv, nonce)
        boolean sigmaOneValid = CryptoUtils.verifyEd25519(
                device.getPublicKey(),
                nonce,
                request.getSignedNonce()
        );

        if (!sigmaOneValid) {
            log.warn("σ₁ invalide pour did={}", request.getDid());
            // Incrémenter le compteur d'anomalies
            anomalyService.recordChallengeFailure(request.getDid());
            throw new InvalidSignatureException(
                    "Signature σ₁ invalide — vérification Ed25519 échouée");
        }

        // ──────────────────────────────────────────────────────
        // Signature valide → Séquence d'activation
        // ──────────────────────────────────────────────────────

        // 5. Émettre le Verifiable Credential (W3C VC)
        VerifiableCredential vc = vcService.issueCredential(device);
        log.info("VC émis — vcId={}", vc.getVcId());

        // 6. Publier le DID Document sur Algorand
        String txId = algorandService.publishDidDocument(
                device.getDid(),
                device.getPublicKey(),
                buildMetadata(device)
        );
        log.info("DID publié on-chain — txId={}", txId);

        // 7. Activer le device en PostgreSQL
        device.setStatus(DeviceStatus.ACTIVE);
        device.setAlgorandTxId(txId);
        device.setActivatedAt(LocalDateTime.now());
        deviceRepository.save(device);

        // 8. Peupler le cache Redis (TTL = 5 minutes)
        redisService.saveDeviceCache(
                device.getDid(),
                device.getPublicKey(),
                vc.getPermissions(),
                redisTtl
        );

        // 9. Réinitialiser les compteurs d'anomalies (device sain)
        redisService.resetFailures(device.getDid(), "challenge");

        // 10. Générer le premier JWT PoP
        JwtPopResponse jwt = jwtService.generateJwtPop(device.getDid(), device.getPublicKey());

        log.info("Device activé — did={}, txId={}", device.getDid(), txId);
        return jwt;
    }

    // ════════════════════════════════════════════════════════════
    // UTILITAIRES PRIVÉS
    // ════════════════════════════════════════════════════════════

    /**
     * Génère un nonce aléatoire de 32 octets encodé en Base64 URL-safe.
     */
    private String generateNonce() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Construit les métadonnées JSON du DID Document.
     */
    private String buildMetadata(Device device) {
        return String.format(
                "{\"type\":\"%s\",\"location\":\"%s\",\"group\":\"%s\",\"serial\":\"%s\"}",
                device.getDeviceType(),
                device.getLocation(),
                device.getLogicalGroup() != null ? device.getLogicalGroup() : "",
                device.getSerialNumber()
        );
    }
}
