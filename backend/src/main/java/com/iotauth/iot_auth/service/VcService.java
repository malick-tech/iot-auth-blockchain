package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.repository.VcRepository;
import com.iotauth.iot_auth.util.CryptoUtils;
import com.iotauth.iot_auth.util.DataIntegrity;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Emission et verification des Verifiable Credentials, profil W3C :
 * VC Data Model 2.0 (validFrom / validUntil, credentialStatus), preuve Data Integrity
 * {@code eddsa-jcs-2022} (proofPurpose assertionMethod), statut par Bitstring Status List.
 */
@Service
@RequiredArgsConstructor
public class VcService {

    public static final String VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
    /** Contexte W3C qui donne un sens (@vocab) aux termes propres au projet, sans contexte JSON-LD heberge. */
    public static final String UNDEFINED_TERMS_CONTEXT_V2 = "https://www.w3.org/ns/credentials/undefined-terms/v2";

    private final VcRepository vcRepository;
    private final AdminKeyService adminKeyService;
    private final ObjectMapper objectMapper;
    private final StatusListService statusListService;

    @Value("${iot.auth.vc-validity-days:365}")
    private int vcValidityDays;

    @Transactional
    public VerifiableCredential issueCredential(Device device) {
        VerifiableCredential vc = new VerifiableCredential();
        // Un identifiant de VC est une URL/URI (VC Data Model 2.0, section 4.4).
        vc.setVcId("urn:uuid:" + UUID.randomUUID());
        vc.setIssuerDid(adminKeyService.getAdminDid());
        vc.setSubjectDid(device.getDid());

        List<String> permissions = derivePermissions(device);
        vc.setPermissions(permissions);
        vc.setIssuedAt(LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS));
        vc.setExpirationDate(vc.getIssuedAt().plusDays(vcValidityDays));

        int statusIndex = statusListService.ensureIndex(device);
        vc.setRawCredential(buildVerifiableCredential(device, vc, permissions, statusIndex));

        return vcRepository.save(vc);
    }

    @Transactional(readOnly = true)
    public Optional<VerifiableCredential> findLatestValidCredential(String did) {
        return vcRepository.findBySubjectDidAndExpirationDateAfter(did, LocalDateTime.now())
                .stream()
                .max(Comparator.comparing(VerifiableCredential::getIssuedAt));
    }

    /**
     * Verifie la preuve Data Integrity de l'Issuer sur le VC : cryptosuite eddsa-jcs-2022,
     * proofPurpose assertionMethod, verificationMethod = methode de l'Issuer attendu.
     */
    public boolean verifyIssuerSignature(String rawCredential) {
        try {
            Map<String, Object> credential = objectMapper.readValue(rawCredential, new TypeReference<Map<String, Object>>() {});
            if (!isVersion2Credential(credential)) {
                return false;
            }
            byte[] publicKey = adminKeyService.getPublicKeyBytes();
            DataIntegrity.verify(
                    credential,
                    (data, signature) -> CryptoUtils.verifyEd25519Bytes(publicKey, data, signature),
                    "assertionMethod",
                    adminKeyService.getVerificationMethod(),
                    null,
                    null);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isVersion2Credential(Map<String, Object> credential) {
        Object context = credential.get("@context");
        Object type = credential.get("type");
        return context instanceof List<?> c && !c.isEmpty() && VC_CONTEXT_V2.equals(c.get(0))
                && type instanceof List<?> t && t.contains("VerifiableCredential");
    }

    private List<String> derivePermissions(Device device) {
        if (device.getLogicalGroup() == null || device.getLogicalGroup().isBlank()) {
            return List.of("device:operate", "device:read");
        }
        return List.of(
                "device:operate",
                "device:read",
                "group:" + device.getLogicalGroup() + ":access"
        );
    }

    private String buildVerifiableCredential(Device device, VerifiableCredential vc, List<String> permissions, int statusIndex) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("id", device.getDid());
        putIfPresent(subject, "serialNumber", device.getSerialNumber());
        putIfPresent(subject, "deviceType", device.getDeviceType());
        putIfPresent(subject, "location", device.getLocation());
        putIfPresent(subject, "logicalGroup", device.getLogicalGroup());
        subject.put("permissions", permissions);

        String validFrom = vc.getIssuedAt().atZone(ZoneId.systemDefault()).toInstant().toString();
        String validUntil = vc.getExpirationDate().atZone(ZoneId.systemDefault()).toInstant().toString();

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("@context", List.of(VC_CONTEXT_V2, UNDEFINED_TERMS_CONTEXT_V2));
        root.put("id", vc.getVcId());
        root.put("type", List.of("VerifiableCredential", "IoTDeviceCredential"));
        root.put("issuer", vc.getIssuerDid());
        root.put("validFrom", validFrom);
        root.put("validUntil", validUntil);
        root.put("credentialSubject", subject);
        root.put("credentialStatus", statusListService.credentialStatusEntries(statusIndex));

        Map<String, Object> secured = DataIntegrity.addProof(
                root,
                adminKeyService::signBytes,
                adminKeyService.getVerificationMethod(),
                "assertionMethod",
                validFrom,
                null,
                null);
        try {
            return objectMapper.writeValueAsString(secured);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Impossible de serialiser le Verifiable Credential", e);
        }
    }

    private static void putIfPresent(Map<String, Object> target, String key, String value) {
        if (value != null && !value.isBlank()) {
            target.put(key, value);
        }
    }
}
