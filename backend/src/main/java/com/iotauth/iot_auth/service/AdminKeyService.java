package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.util.CryptoUtils;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Slf4j
@Component
@Getter
public class AdminKeyService {

    private final String adminPrivateKeyBase64;
    private final long algorandAppId;
    private final String algorandNetwork;

    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private String publicKeyBase32;
    private String adminDid;

    public AdminKeyService(
            @Value("${iot.auth.admin-private-key-base64:}") String adminPrivateKeyBase64,
            @Value("${iot.auth.algorand.app-id}") long algorandAppId,
            @Value("${iot.auth.algorand.network:mainnet}") String algorandNetwork
    ) {
        this.adminPrivateKeyBase64 = adminPrivateKeyBase64;
        this.algorandAppId = algorandAppId;
        this.algorandNetwork = algorandNetwork;
    }

    @PostConstruct
    private void init() {
        if (adminPrivateKeyBase64 == null || adminPrivateKeyBase64.isBlank()) {
            log.warn("Aucune cle privee Admin fournie, generation d'une cle ephemere en memoire.");
            this.privateKeyBytes = CryptoUtils.generateEd25519PrivateKeyBytes();
        } else {
            this.privateKeyBytes = Base64.getDecoder().decode(adminPrivateKeyBase64.trim());
            if (this.privateKeyBytes.length != 32) {
                throw new IllegalStateException("La cle privee Admin doit contenir exactement 32 octets Base64.");
            }
        }
        this.publicKeyBytes = CryptoUtils.deriveEd25519PublicKeyBytes(this.privateKeyBytes);
        this.publicKeyBase32 = CryptoUtils.encodeBase32(this.publicKeyBytes);
        this.adminDid = CryptoUtils.buildDid(this.publicKeyBase32, algorandAppId, algorandNetwork);
        log.info("Admin DID initialise : {}", this.adminDid);
    }

    public String sign(String payload) {
        return CryptoUtils.signEd25519(this.privateKeyBytes, payload);
    }
}
