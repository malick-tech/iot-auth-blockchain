package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.dto.request.ChallengeAnswerRequest;
import com.iotauth.iot_auth.dto.request.FirstContactRequest;
import com.iotauth.iot_auth.dto.response.ChallengeResponse;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.exception.DeviceAlreadyExistsException;
import com.iotauth.iot_auth.exception.DeviceNotFoundException;
import com.iotauth.iot_auth.exception.InvalidDeviceStatusException;
import com.iotauth.iot_auth.exception.InvalidSignatureException;
import com.iotauth.iot_auth.exception.NonceExpiredException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.util.CryptoUtils;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class EnrollmentService {

    private final DeviceRepository deviceRepository;
    private final RedisService redisService;
    private final AlgorandService algorandService;
    private final JwtService jwtService;
    private final VcService vcService;
    private final AnomalyDetectionService anomalyService;

    @Value("${iot.auth.nonce-ttl-seconds:60}")
    private long nonceTtl;

    @Value("${iot.auth.redis-ttl-seconds:300}")
    private long redisTtl;

    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public ChallengeResponse handleFirstContact(FirstContactRequest request) {
        log.info("Premier contact — deviceId={}", request.deviceId());

        Device device = deviceRepository.findByDeviceId(request.deviceId())
                .orElseThrow(() -> DeviceNotFoundException.byDeviceId(request.deviceId()));

        if (device.getStatus() != DeviceStatus.PENDING) {
            throw new InvalidDeviceStatusException(
                    "Premier contact refusé — statut actuel : " + device.getStatus() + " (PENDING requis)");
        }

        if (!CryptoUtils.validateDidFormat(request.did(), request.publicKey())) {
            throw new InvalidSignatureException("DID incohérent avec la clé publique : " + request.did());
        }

        String messageToVerify = request.deviceId() + request.did();
        boolean sigmaZeroValid = CryptoUtils.verifyEd25519(
                request.publicKey(),
                messageToVerify,
                request.signature()
        );

        if (!sigmaZeroValid) {
            log.warn("Signature de premier contact invalide pour deviceId={}", request.deviceId());
            throw new InvalidSignatureException("Signature de premier contact invalide");
        }

        if (deviceRepository.existsByDid(request.did())) {
            throw new DeviceAlreadyExistsException("Ce DID est déjà utilisé : " + request.did());
        }

        device.setDid(request.did());
        device.setPublicKey(request.publicKey());
        device.setStatus(DeviceStatus.PRE_REGISTERED);
        deviceRepository.save(device);

        String nonce = generateNonce();
        redisService.saveNonce(request.did(), nonce, nonceTtl);

        log.info("Premier contact valide — nonce émis pour did={}", request.did());
        return new ChallengeResponse(request.did(), nonce, nonceTtl);
    }

    @Transactional
    public JwtPopResponse handleChallengeResponse(ChallengeAnswerRequest request) {
        log.info("Réponse au challenge — did={}", request.did());

        String nonce = redisService.getNonce(request.did());
        if (nonce == null) {
            throw new NonceExpiredException(request.did());
        }
        redisService.deleteNonce(request.did());

        Device device = deviceRepository.findByDid(request.did())
                .orElseThrow(() -> DeviceNotFoundException.byDid(request.did()));

        if (device.getStatus() != DeviceStatus.PRE_REGISTERED) {
            throw new InvalidDeviceStatusException(
                    "Challenge refusé — statut actuel : " + device.getStatus() + " (PRE_REGISTERED requis)");
        }

        boolean sigmaOneValid = CryptoUtils.verifyEd25519(
                device.getPublicKey(),
                nonce,
                request.signedNonce()
        );

        if (!sigmaOneValid) {
            log.warn("Signature de challenge invalide pour did={}", request.did());
            anomalyService.recordChallengeFailure(request.did());
            throw new InvalidSignatureException("Signature de challenge invalide");
        }

        VerifiableCredential vc = vcService.issueCredential(device);
        log.info("VC émis — credentialId={}", vc.getCredentialId());

        String txId = algorandService.publishDidDocument(device.getDid(), device.getPublicKey(), device.getMetadataJson());

        device.setStatus(DeviceStatus.ACTIVE);
        device.setAlgorandTxId(txId);
        device.setActivatedAt(LocalDateTime.now());
        deviceRepository.save(device);

        redisService.saveDeviceCache(device.getDid(), device.getPublicKey(), vc.getClaimsJson(), redisTtl);
        redisService.resetFailures(device.getDid(), "challenge");

        log.info("Device activé — did={}, txId={}", device.getDid(), txId);
        return jwtService.generateJwtPop(device.getDid(), device.getPublicKey());
    }

    private String generateNonce() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
