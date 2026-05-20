package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import com.iotauth.iot_auth.repository.VcRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class VcService {

    private final VcRepository vcRepository;

    public VerifiableCredential issueCredential(Device device) {
        String credentialId = "vc:" + UUID.randomUUID();
        String claimsJson = "{\"deviceId\":\"" + device.getDeviceId() + "\",\"did\":\"" + device.getDid() + "\"}";
        VerifiableCredential credential = VerifiableCredential.builder()
                .credentialId(credentialId)
                .device(device)
                .issuer("did:algo:iot-auth")
                .subject(device.getDid())
                .claimsJson(claimsJson)
                .proofJson("{}")
                .vcHash(sha256(claimsJson))
                .issuedAt(Instant.now())
                .build();
        return vcRepository.save(credential);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available", e);
        }
    }
}
