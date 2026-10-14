package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.repository.DeviceRepository;
import com.iotauth.iot_auth.util.BitstringStatusList;
import com.iotauth.iot_auth.util.DataIntegrity;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bitstring Status List v1.0 (W3C).
 * <p>
 * Deux listes publiques, derivees de l'etat PostgreSQL (source de verite) :
 * <ul>
 *   <li>{@code revocation} : bit a 1 pour un dispositif REVOKED (irreversible) ;</li>
 *   <li>{@code suspension} : bit a 1 pour un dispositif SUSPENDED (reversible).</li>
 * </ul>
 * Ces listes servent les verificateurs tiers qui ne connaissent que le VC. Le chemin d'authentification
 * du backend continue d'utiliser PostgreSQL, Redis et Algorand, plus rapides et deja fail-closed.
 */
@Service
@RequiredArgsConstructor
public class StatusListService {

    public static final String PURPOSE_REVOCATION = "revocation";
    public static final String PURPOSE_SUSPENSION = "suspension";

    private final DeviceRepository deviceRepository;
    private final AdminKeyService adminKeyService;
    private final ObjectMapper objectMapper;

    @Value("${iot.auth.public-base-url:http://localhost:8083}")
    private String publicBaseUrl;

    @Value("${iot.auth.status-list.size-bits:131072}")
    private int sizeBits;

    public static boolean isValidPurpose(String purpose) {
        return PURPOSE_REVOCATION.equals(purpose) || PURPOSE_SUSPENSION.equals(purpose);
    }

    public String listUrl(String purpose) {
        return publicBaseUrl + "/api/v1/status-lists/" + purpose;
    }

    /** Attribue un index de statut au dispositif s'il n'en a pas encore (a appeler dans une transaction). */
    @Transactional
    public int ensureIndex(Device device) {
        if (device.getStatusListIndex() != null) {
            return device.getStatusListIndex();
        }
        int next = deviceRepository.findMaxStatusListIndex() + 1;
        if (next >= sizeBits) {
            throw new IllegalStateException("Liste de statuts pleine (" + sizeBits + " entrees) : creer une nouvelle liste");
        }
        device.setStatusListIndex(next);
        deviceRepository.save(device);
        return next;
    }

    /** Entrees credentialStatus a placer dans le VC d'un dispositif. */
    public List<Map<String, Object>> credentialStatusEntries(int index) {
        return List.of(entry(PURPOSE_REVOCATION, index), entry(PURPOSE_SUSPENSION, index));
    }

    private Map<String, Object> entry(String purpose, int index) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("id", listUrl(purpose) + "#" + index);
        e.put("type", "BitstringStatusListEntry");
        e.put("statusPurpose", purpose);
        e.put("statusListIndex", String.valueOf(index));
        e.put("statusListCredential", listUrl(purpose));
        return e;
    }

    /** Construit et signe (assertionMethod) le BitstringStatusListCredential pour la finalite demandee. */
    @Transactional(readOnly = true)
    public String buildStatusListCredential(String purpose) {
        if (!isValidPurpose(purpose)) {
            throw new IllegalArgumentException("Finalite de statut inconnue : " + purpose);
        }
        DeviceStatus flagged = PURPOSE_REVOCATION.equals(purpose) ? DeviceStatus.REVOKED : DeviceStatus.SUSPENDED;
        BitstringStatusList list = new BitstringStatusList(sizeBits);
        for (Device d : deviceRepository.findByStatus(flagged)) {
            if (d.getStatusListIndex() != null) {
                list.set(d.getStatusListIndex(), true);
            }
        }

        String id = listUrl(purpose);
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("id", id + "#list");
        subject.put("type", "BitstringStatusList");
        subject.put("statusPurpose", purpose);
        subject.put("encodedList", list.encode());

        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("@context", List.of(VcService.VC_CONTEXT_V2));
        vc.put("id", id);
        vc.put("type", List.of("VerifiableCredential", "BitstringStatusListCredential"));
        vc.put("issuer", adminKeyService.getAdminDid());
        vc.put("validFrom", now);
        vc.put("credentialSubject", subject);

        Map<String, Object> secured = DataIntegrity.addProof(
                vc, adminKeyService::signBytes, adminKeyService.getVerificationMethod(),
                "assertionMethod", now, null, null);
        try {
            return objectMapper.writeValueAsString(secured);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Impossible de serialiser la liste de statuts", e);
        }
    }
}
