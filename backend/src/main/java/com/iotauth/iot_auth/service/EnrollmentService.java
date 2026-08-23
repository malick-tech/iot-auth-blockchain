package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.dto.request.ChallengeResponseRequest;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class EnrollmentService {

    private final DeviceRepository deviceRepository;
    private final RedisService redisService;
    private final AlgorandService algorandService;
    private final JwtService jwtService;
    private final VcService vcService;
    private final AuditLogService auditLogService;
    private final AnomalyDetectionService anomalyService;
    @Autowired(required = false)
    private AdminKeyService adminKeyService;

    @Value("${iot.auth.nonce-ttl-seconds:60}")
    private long nonceTtl;

    @Value("${iot.auth.redis-ttl-seconds:300}")
    private long redisTtl;

    @Value("${iot.auth.algorand.app-id}")
    private long algorandAppId;

    @Value("${iot.auth.algorand.network:mainnet}")
    private String algorandNetwork;

    @Transactional
    public ChallengeResponse handleFirstContact(FirstContactRequest request) {
        log.info("Premier contact - serial={}", request.getSerialNumber());
        auditLogService.record(
                EventType.FIRST_CONTACT_RECEIVED,
                request.getDid(),
                ActorType.DEVICE,
                true,
                "Premier contact recu pour le numero de serie " + request.getSerialNumber()
        );

        Device device = deviceRepository.findBySerialNumber(request.getSerialNumber())
                .orElseThrow(() -> {
                    auditFirstContactRejected(request, "Dispositif introuvable");
                    return DeviceNotFoundException.bySerial(request.getSerialNumber());
                });

        if (device.getStatus() != DeviceStatus.PENDING) {
            auditFirstContactRejected(request, "Statut invalide : " + device.getStatus());
            throw InvalidDeviceStatusException.expected(DeviceStatus.PENDING, device.getStatus());
        }

        if (!CryptoUtils.validateDidFormat(request.getDid(), request.getPublicKey(), algorandAppId, algorandNetwork)) {
            auditFirstContactRejected(request, "DID incoherent avec la cle publique");
            throw new InvalidSignatureException("DID incoherent avec la cle publique : " + request.getDid());
        }

        String messageToVerify = request.getSerialNumber() + request.getDid();
        boolean sigmaZeroValid = CryptoUtils.verifyEd25519(
                request.getPublicKey(),
                messageToVerify,
                request.getSignature()
        );

        if (!sigmaZeroValid) {
            log.warn("Signature sigma0 invalide pour serial={}", request.getSerialNumber());
            auditFirstContactRejected(request, "Signature sigma0 invalide");
            throw new InvalidSignatureException("Signature sigma0 invalide - verification Ed25519 echouee");
        }

        if (deviceRepository.existsByDid(request.getDid())) {
            auditFirstContactRejected(request, "DID deja utilise");
            throw DeviceAlreadyExistsException.byDid(request.getDid());
        }

        device.setDid(request.getDid());
        device.setPublicKey(request.getPublicKey());
        device.setStatus(DeviceStatus.PRE_REGISTERED);
        device.setLastSeenAt(LocalDateTime.now());
        deviceRepository.save(device);

        String nonce = CryptoUtils.generateNonce();
        redisService.saveNonce(request.getDid(), nonce, nonceTtl);

        auditLogService.record(
                EventType.CHALLENGE_ISSUED,
                request.getDid(),
                ActorType.SYSTEM,
                true,
                "Challenge nonce emis apres validation du premier contact"
        );
        log.info("Signature sigma0 valide - nonce emis pour did={}", request.getDid());

        return ChallengeResponse.builder()
                .nonce(nonce)
                .did(request.getDid())
                .expiresIn(nonceTtl)
                .build();
    }

    @Transactional
    public JwtPopResponse handleChallengeResponse(ChallengeResponseRequest request) {
        log.info("Reponse au challenge - did={}", request.getDid());

        String nonce = redisService.getNonce(request.getDid());
        if (nonce == null) {
            auditChallengeFailed(request.getDid(), "Nonce expire ou introuvable");
            throw new NonceExpiredException(request.getDid());
        }

        redisService.deleteNonce(request.getDid());

        Device device = deviceRepository.findByDid(request.getDid())
                .orElseThrow(() -> {
                    auditChallengeFailed(request.getDid(), "Dispositif introuvable");
                    return DeviceNotFoundException.byDid(request.getDid());
                });

        if (device.getStatus() != DeviceStatus.PRE_REGISTERED) {
            // Un device en PUBLISHING indique un crash après la publication Algorand
            // mais avant le commit ACTIVE. Ce cas doit être traité par l'admin.
            if (device.getStatus() == DeviceStatus.PUBLISHING) {
                auditChallengeFailed(request.getDid(), "Enrolement incomplet detecte (statut PUBLISHING) - intervention admin requise");
                throw new InvalidSignatureException(
                    "Enrolement incomplet pour did=" + request.getDid() +
                    " : le DID a peut-etre deja ete publie on-chain. Contactez l'administrateur."
                );
            }
            auditChallengeFailed(request.getDid(), "Statut invalide : " + device.getStatus());
            throw InvalidDeviceStatusException.expected(DeviceStatus.PRE_REGISTERED, device.getStatus());
        }
        boolean sigmaOneValid = CryptoUtils.verifyEd25519(
                device.getPublicKey(),
                nonce,
                request.getSignedNonce()
        );

        if (!sigmaOneValid) {
            log.warn("Signature sigma1 invalide pour did={}", request.getDid());
            anomalyService.recordChallengeFailure(request.getDid());
            auditChallengeFailed(request.getDid(), "Signature sigma1 invalide");
            throw new InvalidSignatureException("Signature sigma1 invalide - verification Ed25519 echouee");
        }

        auditLogService.record(
                EventType.CHALLENGE_VALIDATED,
                request.getDid(),
                ActorType.DEVICE,
                true,
                "Challenge valide par signature sigma1"
        );

        VerifiableCredential vc = vcService.issueCredential(device);
        auditLogService.record(
                EventType.VC_ISSUED,
                device.getDid(),
                ActorType.SYSTEM,
                true,
                "Verifiable Credential emis : " + vc.getVcId()
        );
        log.info("VC emis - vcId={}", vc.getVcId());

        // Marquage transitoire PUBLISHING : si le process crashe après la confirmation
        // Algorand mais avant le flush ACTIVE, l'admin verra ce statut en base et pourra
        // réactiver le device manuellement — évitant ainsi un DID orphelin on-chain.
        device.setStatus(DeviceStatus.PUBLISHING);
        deviceRepository.saveAndFlush(device);

        String txId = algorandService.publishDidDocument(
                device.getDid(),
                device.getPublicKey(),
                buildMetadata(device)
        );
        auditLogService.record(
                EventType.ALGORAND_PUBLICATION_CONFIRMED,
                device.getDid(),
                ActorType.SYSTEM,
                true,
                "DID publie sur Algorand : " + txId
        );
        log.info("DID publie on-chain - txId={}", txId);

        LocalDateTime now = LocalDateTime.now();
        device.setStatus(DeviceStatus.ACTIVE);
        device.setAlgorandTxId(txId);
        device.setActivatedAt(now);
        device.setLastSeenAt(now);
        deviceRepository.save(device);

        saveDeviceCacheForGateway(device, vc.getPermissions());

        anomalyService.resetChallengeFailures(device.getDid());

        JwtPopResponse jwt = jwtService.generateJwtPop(device.getDid(), device.getPublicKey());
        jwt.setPermissions(vc.getPermissions());
        jwt.setCredentialId(vc.getVcId());
        jwt.setVerifiableCredential(vc.getRawCredential());
        jwt.setDeviceSerialNumber(device.getSerialNumber());
        auditLogService.record(
                EventType.DEVICE_ACTIVATED,
                device.getDid(),
                ActorType.SYSTEM,
                true,
                "Dispositif active apres enrolement"
        );
        auditLogService.record(
                EventType.JWT_ISSUED,
                device.getDid(),
                ActorType.SYSTEM,
                true,
                "Premier JWT PoP emis"
        );

        log.info("Device active - did={}, txId={}", device.getDid(), txId);
        return jwt;
    }

    private String buildMetadata(Device device) {
        return String.format(
                "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],"
                        + "\"id\":\"%s\","
                        + "\"publicKey\":\"%s\","
                        + "\"verificationMethod\":[{\"id\":\"%s#key-1\",\"type\":\"Ed25519VerificationKey2020\","
                        + "\"controller\":\"%s\",\"publicKeyBase32\":\"%s\"}],"
                        + "\"authentication\":[\"%s#key-1\"],"
                        + "\"assertionMethod\":[\"%s#key-1\"],"
                        + "\"service\":[{\"id\":\"%s#metadata\",\"type\":\"IoTDeviceMetadata\","
                        + "\"serviceEndpoint\":\"urn:iot-auth:device:%s\","
                        + "\"metadata\":{\"type\":\"%s\",\"location\":\"%s\",\"group\":\"%s\",\"serial\":\"%s\"}}]}",
                safeMetadataValue(device.getDid()),
                safeMetadataValue(device.getPublicKey()),
                safeMetadataValue(device.getDid()),
                safeMetadataValue(device.getDid()),
                safeMetadataValue(device.getPublicKey()),
                safeMetadataValue(device.getDid()),
                safeMetadataValue(device.getDid()),
                safeMetadataValue(device.getDid()),
                safeMetadataValue(device.getSerialNumber()),
                safeMetadataValue(device.getDeviceType()),
                safeMetadataValue(device.getLocation()),
                safeMetadataValue(device.getLogicalGroup()),
                safeMetadataValue(device.getSerialNumber())
        );
    }

    private String safeMetadataValue(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String issuerPublicKey() {
        return adminKeyService != null ? adminKeyService.getPublicKeyBase32() : null;
    }

    private String issuerDid() {
        return adminKeyService != null ? adminKeyService.getAdminDid() : null;
    }

    private void saveDeviceCacheForGateway(Device device, java.util.List<String> permissions) {
        if (adminKeyService == null) {
            redisService.saveDeviceCache(device.getDid(), device.getPublicKey(), permissions, redisTtl);
            return;
        }

        redisService.saveDeviceCache(
                device.getDid(),
                device.getPublicKey(),
                permissions,
                issuerPublicKey(),
                issuerDid(),
                redisTtl
        );
    }

    private void auditFirstContactRejected(FirstContactRequest request, String reason) {
        auditLogService.record(
                EventType.FIRST_CONTACT_REJECTED,
                request.getDid(),
                ActorType.DEVICE,
                false,
                reason
        );
    }

    private void auditChallengeFailed(String did, String reason) {
        auditLogService.record(
                EventType.CHALLENGE_FAILED,
                did,
                ActorType.DEVICE,
                false,
                reason
        );
    }
}
