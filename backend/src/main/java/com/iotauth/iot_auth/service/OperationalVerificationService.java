package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.AlgorandBoxPrefix;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.dto.request.CacheHitLogRequest;
import com.iotauth.iot_auth.dto.request.OperationalVerifyRequest;
import com.iotauth.iot_auth.dto.response.OperationalVerifyResponse;
import com.iotauth.iot_auth.repository.VcRepository;
import com.iotauth.iot_auth.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OperationalVerificationService {

    private final JwtService jwtService;
    private final AlgorandService algorandService;
    private final VcRepository vcRepository;
    private final RedisService redisService;
    private final DeviceRepository deviceRepository;
    private final AuditLogService auditLogService;
    private final AnomalyDetectionService anomalyService;
    private final DeviceMetricService deviceMetricService;
    @Autowired(required = false)
    private AdminKeyService adminKeyService;


    @Value("${iot.auth.redis-ttl-seconds:300}")
    private long redisTtl;

    @Value("${iot.auth.pop-freshness-seconds:30}")
    private long popFreshnessSeconds;

    public OperationalVerifyResponse verify(OperationalVerifyRequest request) {
        JwtService.JwtClaims claims;
        try {
            claims = jwtService.verifyJwtPop(request.getJwt());
        } catch (Exception e) {
            return rejected(request.getDid(), "JWT invalide : " + e.getMessage());
        }

        if (!claims.getSub().equals(request.getDid())) {
            return rejected(request.getDid(), "DID incohérent entre la requête et le JWT");
        }

        if (claims.getExp() < Instant.now().getEpochSecond()) {
            return rejected(request.getDid(), "JWT PoP expiré");
        }

        // Résolution on-chain : source de vérité en cas de cache MISS
        Optional<byte[]> docBox = algorandService.readBox(AlgorandBoxPrefix.DOCUMENT, request.getDid());
        Optional<byte[]> statusBox = algorandService.readBox(AlgorandBoxPrefix.STATUS, request.getDid());

        if (docBox.isEmpty() || statusBox.isEmpty()) {
            return rejected(request.getDid(), "DID introuvable on-chain");
        }

        String status = new String(statusBox.get(), StandardCharsets.UTF_8);
        if (!"ACTIVE".equals(status)) {
            if ("REVOKED".equals(status)) {
                auditLogService.record(
                        EventType.REVOKED_DEVICE_ACCESS_ATTEMPT,
                        request.getDid(),
                        ActorType.DEVICE,
                        false,
                        "Tentative opérationnelle (cache MISS) sur DID révoqué on-chain"
                );
            }
            return rejected(request.getDid(), "Dispositif non actif on-chain : " + status);
        }

        Optional<Device> deviceOpt = deviceRepository.findByDid(request.getDid());
        if (deviceOpt.isEmpty()) {
            return rejected(request.getDid(), "Dispositif introuvable en base");
        }
        Device device = deviceOpt.get();
        DeviceStatus dbStatus = device.getStatus();
        if (dbStatus != DeviceStatus.ACTIVE) {
            if (dbStatus == DeviceStatus.REVOKED) {
                auditLogService.record(
                        EventType.REVOKED_DEVICE_ACCESS_ATTEMPT,
                        request.getDid(),
                        ActorType.DEVICE,
                        false,
                        "Tentative opérationnelle (cache MISS) sur DID révoqué (PostgreSQL)"
                );
            }
            return rejected(request.getDid(), "Dispositif non actif (PostgreSQL) : " + dbStatus);
        }

        String publicKeyBase32;
        try {
            Map<String, Object> docJson = jwtService.readJsonMap(new String(docBox.get(), StandardCharsets.UTF_8));
            // Bug 9 fix : utilisation de String.valueOf() au lieu du cast direct pour éviter
            // un ClassCastException silencieux si Jackson désérialise la valeur autrement
            // qu'en String (ex: null, nombre). On vérifie ensuite le contenu.
            Object rawPubKey = docJson.get("publicKey");
            if (rawPubKey == null) {
                return rejected(request.getDid(), "Clé publique absente du DID Document on-chain");
            }
            publicKeyBase32 = String.valueOf(rawPubKey);
            if (publicKeyBase32.isBlank() || "null".equals(publicKeyBase32)) {
                return rejected(request.getDid(), "Clé publique absente du DID Document on-chain");
            }
        } catch (Exception e) {
            return rejected(request.getDid(), "DID Document on-chain illisible");
        }

        // Vérification de la preuve de possession (fraîcheur + signature)
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - request.getTimestamp()) > popFreshnessSeconds) {
            return rejected(request.getDid(), "Preuve de possession non fraîche");
        }

        String proofMessage = claims.getJti() + ":" + request.getTimestamp();
        boolean proofValid = CryptoUtils.verifyEd25519(
                publicKeyBase32,
                proofMessage,
                request.getProofSignature()
        );
        if (!proofValid) {
            return rejected(request.getDid(), "Preuve de possession invalide");
        }

        List<String> permissions = vcRepository
                .findBySubjectDidAndExpirationDateAfter(request.getDid(), LocalDateTime.now())
                .stream()
                .findFirst()
                .map(VerifiableCredential::getPermissions)
                .orElse(List.of());

        if (request.getRequestedPermission() != null
                && !request.getRequestedPermission().isBlank()
                && !permissions.contains(request.getRequestedPermission())) {
            auditLogService.record(
                    EventType.PERMISSION_VIOLATION,
                    request.getDid(),
                    ActorType.DEVICE,
                    false,
                    "Permission non accordée (cache MISS) : " + request.getRequestedPermission()
            );
            // Déclencheur 3 : violation de permission, suspension immédiate
            // (pas d'accumulation, contrairement aux déclencheurs 1 et 2).
            anomalyService.recordPermissionViolation(request.getDid());
            return rejected(request.getDid(), "Permission non accordée : " + request.getRequestedPermission());
        }

        device.setLastSeenAt(LocalDateTime.now());
        deviceRepository.save(device);

        saveDeviceCacheForGateway(request.getDid(), publicKeyBase32, status, permissions);

        // Persister les métriques IoT reçues dans ce paquet opérationnel.
        // L'appel est best-effort : une erreur de persistance ne bloque pas la réponse.
        deviceMetricService.saveMetrics(request.getDid(), request.getMetrics());

        log.info("Vérification opérationnelle (cache MISS) réussie pour did={}", request.getDid());

        auditLogService.record(
                EventType.AUTH_CACHE_MISS,
                request.getDid(),
                ActorType.DEVICE,
                true,
                "Vérification opérationnelle autorisée (résolution on-chain + PostgreSQL), permissions=" + permissions
        );

        return OperationalVerifyResponse.builder()
                .authorized(true)
                .did(request.getDid())
                .status(status)
                .permissions(permissions)
            .metrics(request.getMetrics())
                .build();
    }

    private OperationalVerifyResponse rejected(String did, String reason) {
        log.warn("Vérification opérationnelle refusée pour did={} : {}", did, reason);
        auditLogService.record(
                EventType.AUTH_CACHE_MISS,
                did,
                ActorType.DEVICE,
                false,
                "Vérification opérationnelle refusée : " + reason
        );
        return OperationalVerifyResponse.builder()
                .authorized(false)
                .did(did)
                .reason(reason)
                .build();
    }

    private String issuerPublicKey() {
        return adminKeyService != null ? adminKeyService.getPublicKeyBase32() : null;
    }

    private String issuerDid() {
        return adminKeyService != null ? adminKeyService.getAdminDid() : null;
    }

    private void saveDeviceCacheForGateway(
            String did,
            String publicKeyBase32,
            String status,
            List<String> permissions
    ) {
        if (adminKeyService == null) {
            redisService.saveDeviceCache(did, publicKeyBase32, status, permissions, redisTtl);
            return;
        }

        redisService.saveDeviceCache(
                did,
                publicKeyBase32,
                status,
                permissions,
                issuerPublicKey(),
                issuerDid(),
                redisTtl
        );
    }

    /**
     * Reçoit, en tâche de fond depuis la Gateway, la trace d'une décision prise
     * localement (cache HIT) — pour que le SOC ait une visibilité complète même
     * sur les requêtes opérationnelles qui ne touchent jamais Spring Boot.
     */
    public void logCacheHitDecision(CacheHitLogRequest request) {
        String details = request.getReason() != null
                ? request.getReason()
                : (request.isAuthorized() ? "Autorisé par la Gateway (cache HIT)" : "Refusé par la Gateway (cache HIT)");

        if (request.getRequestedPermission() != null && !request.getRequestedPermission().isBlank()) {
            details += " | permission demandée: " + request.getRequestedPermission();
        }

        auditLogService.record(
                EventType.AUTH_CACHE_HIT,
                request.getDid(),
                ActorType.DEVICE,
                request.isAuthorized(),
                details,
                "{\"requestedPermission\":\"" + jsonEscape(request.getRequestedPermission()) + "\",\"violationType\":\""
                        + jsonEscape(request.getViolationType()) + "\",\"decisionSource\":\"GATEWAY_CACHE_HIT\"}",
                null
        );

        // Déclencheur 3 étendu au cache HIT : une violation de permission
        // détectée localement par la Gateway déclenche aussi la suspension
        // automatique, exactement comme en cache MISS.
        if (request.isAuthorized()) {
            deviceRepository.findByDid(request.getDid()).ifPresent(device -> {
                device.setLastSeenAt(LocalDateTime.now());
                deviceRepository.save(device);
            });
        }

        if ("PERMISSION_VIOLATION".equals(request.getViolationType())) {
            anomalyService.recordPermissionViolation(request.getDid());
        }
    }

    private String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
