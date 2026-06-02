package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.repository.VcRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VcService {

    private final VcRepository vcRepository;
    private final AdminKeyService adminKeyService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${iot.auth.vc-validity-days:365}")
    private int vcValidityDays;

    @Transactional
    public VerifiableCredential issueCredential(Device device) {
        VerifiableCredential vc = new VerifiableCredential();
        vc.setVcId("vc-" + UUID.randomUUID());
        vc.setIssuerDid(adminKeyService.getAdminDid());
        vc.setSubjectDid(device.getDid());

        List<String> permissions = derivePermissions(device);
        vc.setPermissions(permissions);
        vc.setIssuedAt(LocalDateTime.now());
        vc.setExpirationDate(vc.getIssuedAt().plusDays(vcValidityDays));

        String rawCredential = buildVerifiableCredential(device, vc, permissions);
        vc.setRawCredential(rawCredential);

        return vcRepository.save(vc);
    }

    @Transactional(readOnly = true)
    public Optional<VerifiableCredential> findLatestValidCredential(String did) {
        return vcRepository.findBySubjectDidAndExpirationDateAfter(did, LocalDateTime.now())
                .stream()
                .max(Comparator.comparing(VerifiableCredential::getIssuedAt));
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

    private String buildVerifiableCredential(Device device, VerifiableCredential vc, List<String> permissions) {
        ObjectNode root = objectMapper.createObjectNode();
        ArrayNode context = root.putArray("@context");
        context.add("https://www.w3.org/2018/credentials/v1");
        root.putArray("type").add("VerifiableCredential").add("IoTDeviceCredential");
        root.put("id", vc.getVcId());
        root.put("issuer", vc.getIssuerDid());
        root.put("issuanceDate", vc.getIssuedAt().toString());
        root.put("expirationDate", vc.getExpirationDate().toString());

        ObjectNode subject = root.putObject("credentialSubject");
        subject.put("id", device.getDid());
        subject.put("serialNumber", device.getSerialNumber());
        subject.put("deviceType", device.getDeviceType());
        subject.put("location", device.getLocation());
        subject.put("logicalGroup", device.getLogicalGroup());

        ArrayNode permissionArray = root.putArray("permissions");
        permissions.forEach(permissionArray::add);

        ObjectNode proof = root.putObject("proof");
        proof.put("type", "Ed25519Signature2020");
        proof.put("created", vc.getIssuedAt().toString());
        proof.put("verificationMethod", vc.getIssuerDid() + "#key-1");
        proof.put("proofPurpose", "assertionMethod");
        proof.put("proofValue", "");

        String unsignedCredential = serialize(root);
        String proofValue = adminKeyService.sign(unsignedCredential);
        proof.put("proofValue", proofValue);

        return serialize(root);
    }

    private String serialize(ObjectNode node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Impossible de serialiser le Verifiable Credential", e);
        }
    }
}
