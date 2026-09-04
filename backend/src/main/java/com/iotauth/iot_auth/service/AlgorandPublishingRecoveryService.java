package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.AlgorandBoxPrefix;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.repository.DeviceRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Récupère les dispositifs bloqués en statut PUBLISHING.
 *
 * Ce statut transitoire peut persister indéfiniment si le backend crashe
 * entre la soumission de la transaction Algorand et l'écriture du txId en base.
 * Ce service détecte ces orphelins et les récupère automatiquement :
 *
 * <ol>
 *   <li>Vérifie d'abord si le DID est déjà publié on-chain (crash après confirmation).</li>
 *   <li>Si oui → passe directement ACTIVE (idempotent, pas de double publication).</li>
 *   <li>Si non → tente de republier. En cas de succès → ACTIVE.</li>
 *   <li>Après {@code maxRecoveryAttempts} échecs consécutifs → repasse PRE_REGISTERED
 *       pour permettre au dispositif de relancer son enrôlement.</li>
 * </ol>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AlgorandPublishingRecoveryService {

    /** Préfixe du marqueur de compteur stocké dans suspensionReason lors de la récupération. */
    private static final String PUBLISHING_FAILURES_MARKER = "PUBLISHING_FAILURES:";

    private final DeviceRepository deviceRepository;
    private final AlgorandService algorandService;
    private final AuditLogService auditLogService;
    private final EnrollmentMetadataBuilder metadataBuilder;

    @Value("${iot.auth.algorand.recovery.max-attempts:3}")
    private int maxRecoveryAttempts;

    /**
     * Exécuté une fois au démarrage pour récupérer immédiatement les orphelins
     * qui auraient survécu à un crash précédent.
     */
    @PostConstruct
    public void recoverOnStartup() {
        log.info("Démarrage : scan des dispositifs PUBLISHING orphelins...");
        recoverPublishingOrphans();
    }

    /**
     * Scan périodique toutes les 5 minutes pour attraper les orphelins apparus
     * après le démarrage (transaction expirée, timeout réseau, etc.).
     */
    @Scheduled(fixedDelayString = "${iot.auth.algorand.recovery.scan-interval-ms:300000}",
               initialDelayString = "${iot.auth.algorand.recovery.initial-delay-ms:60000}")
    public void recoverPeriodically() {
        recoverPublishingOrphans();
    }

    @Transactional
    public void recoverPublishingOrphans() {
        List<Device> orphans = deviceRepository.findByStatus(DeviceStatus.PUBLISHING);
        if (orphans.isEmpty()) {
            return;
        }

        log.warn("Récupération Algorand : {} dispositif(s) PUBLISHING détecté(s)", orphans.size());

        for (Device device : orphans) {
            tryRecover(device);
        }
    }

    private void tryRecover(Device device) {
        String did = device.getDid();
        log.info("Tentative de récupération pour did={} serial={}", did, device.getSerialNumber());

        // Étape 1 : le DID est-il déjà actif on-chain ?
        // (le backend a peut-être crashé après la confirmation Algorand)
        try {
            var statusBox = algorandService.readBox(AlgorandBoxPrefix.STATUS, did);
            if (statusBox.isPresent()) {
                String onChainStatus = new String(statusBox.get());
                if ("ACTIVE".equals(onChainStatus)) {
                    log.info("DID déjà actif on-chain pour did={} — activation directe sans republication", did);
                    activateDevice(device, device.getAlgorandTxId() != null ? device.getAlgorandTxId() : "recovered-on-chain");
                    return;
                }
            }
        } catch (Exception e) {
            log.warn("Impossible de lire le statut on-chain pour did={} : {}", did, e.getMessage());
        }

        // Étape 2 : tenter la publication (AlgorandService.submitApplicationCall a déjà son propre retry)
        try {
            String metadata = metadataBuilder.build(device);
            String txId = algorandService.publishDidDocument(did, device.getPublicKey(), metadata);
            log.info("Republication réussie pour did={} txId={}", did, txId);
            activateDevice(device, txId);

        } catch (Exception e) {
            log.error("Echec de republication pour did={} : {}", did, e.getMessage());
            int failureCount = incrementPublishingFailures(device);

            if (failureCount >= maxRecoveryAttempts) {
                log.error("did={} dépasse {} tentatives de récupération — retour à PRE_REGISTERED pour re-enrôlement",
                        did, maxRecoveryAttempts);
                revertToPreRegistered(device, failureCount);
            } else {
                log.warn("did={} : {} tentative(s) échouée(s) sur {} — prochaine tentative au prochain scan",
                        did, failureCount, maxRecoveryAttempts);
            }
        }
    }

    private void activateDevice(Device device, String txId) {
        LocalDateTime now = LocalDateTime.now();
        device.setStatus(DeviceStatus.ACTIVE);
        device.setAlgorandTxId(txId);
        device.setActivatedAt(device.getActivatedAt() != null ? device.getActivatedAt() : now);
        device.setLastSeenAt(now);
        deviceRepository.save(device);

        auditLogService.record(
                EventType.DEVICE_ACTIVATED,
                device.getDid(),
                ActorType.SYSTEM,
                true,
                "Dispositif récupéré après blocage PUBLISHING — txId=" + txId
        );
        log.info("Dispositif récupéré et activé : did={}", device.getDid());
    }

    private void revertToPreRegistered(Device device, int failureCount) {
        device.setStatus(DeviceStatus.PRE_REGISTERED);
        deviceRepository.save(device);

        auditLogService.record(
                EventType.ALGORAND_PUBLICATION_FAILED,
                device.getDid(),
                ActorType.SYSTEM,
                false,
                "Publication on-chain impossible après " + failureCount + " tentatives — "
                        + "dispositif repassé en PRE_REGISTERED pour permettre un nouveau challenge-response. "
                        + "serial=" + device.getSerialNumber()
        );
        log.error("did={} repassé en PRE_REGISTERED après {} échecs de publication on-chain",
                device.getDid(), failureCount);
    }

    /**
     * Utilise un champ de la base pour compter les tentatives de récupération.
     * On stocke le compteur dans suspensionReason (champ text disponible) car
     * ajouter une colonne DDL nécessiterait une migration. Ce compteur est
     * réinitialisé lors de l'activation.
     */
    private int incrementPublishingFailures(Device device) {
        String marker = device.getSuspensionReason();
        int count = 1;
        if (marker != null && marker.startsWith(PUBLISHING_FAILURES_MARKER)) {
            try {
                count = Integer.parseInt(marker.substring(PUBLISHING_FAILURES_MARKER.length())) + 1;
            } catch (NumberFormatException ignored) {
                count = 1;
            }
        }
        device.setSuspensionReason(PUBLISHING_FAILURES_MARKER + count);
        deviceRepository.save(device);
        return count;
    }
}
