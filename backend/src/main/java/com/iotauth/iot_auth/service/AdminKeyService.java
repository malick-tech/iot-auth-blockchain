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
            // En production, l'absence de clé persistante invalide tous les JWT et VC
            // existants à chaque redémarrage (la clé change). On lève une erreur explicite
            // pour forcer la configuration de IOT_AUTH_ADMIN_PRIVATE_KEY_BASE64.
            // En développement local, définir la variable d'env ou accepter ce comportement
            // en connaissance de cause.
            log.error("======================================================================");
            log.error("ERREUR DE CONFIGURATION : iot.auth.admin-private-key-base64 est vide.");
            log.error("Tous les JWT et VC existants seront invalides apres chaque redemarrage.");
            log.error("Definir IOT_AUTH_ADMIN_PRIVATE_KEY_BASE64 en variable d'environnement.");
            log.error("Pour generer une cle : openssl rand -base64 32");
            log.error("======================================================================");
            throw new IllegalStateException(
                "La cle privee Admin (IOT_AUTH_ADMIN_PRIVATE_KEY_BASE64) est absente. " +
                "Le serveur refuse de demarrer sans une cle persistante afin d'eviter " +
                "l'invalidation de tous les tokens et credentials existants. " +
                "Consultez les logs pour les instructions de generation."
            );
        }

        this.privateKeyBytes = Base64.getDecoder().decode(adminPrivateKeyBase64.trim());
        if (this.privateKeyBytes.length != 32) {
            throw new IllegalStateException(
                "La cle privee Admin doit contenir exactement 32 octets une fois decodee en Base64 " +
                "(valeur actuelle : " + this.privateKeyBytes.length + " octets). " +
                "Verifiez la variable IOT_AUTH_ADMIN_PRIVATE_KEY_BASE64."
            );
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
