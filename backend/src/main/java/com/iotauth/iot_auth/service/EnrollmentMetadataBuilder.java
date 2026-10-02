package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import org.springframework.stereotype.Component;

/**
 * Construit le DID Document JSON utilisé lors de la publication on-chain (PUBLISH_DID).
 * Extrait de EnrollmentService pour permettre la réutilisation par
 * AlgorandPublishingRecoveryService sans créer de dépendance circulaire.
 */
@Component
public class EnrollmentMetadataBuilder {

    /**
     * Produit le DID Document JSON-LD conforme à la méthode did:algo app namespace.
     * <p>
     * Vie privée : ce document est public et permanent (l'historique de la chaîne
     * n'est jamais effacé). Il ne contient donc que l'identifiant et la clé publique.
     * Le numéro de série, le type, la localisation et le groupe logique restent
     * dans PostgreSQL et ne doivent jamais être publiés on-chain.
     *
     * @param device le dispositif dont le DID Document doit être publié
     * @return JSON-LD sérialisé, prêt à être passé à AlgorandService.publishDidDocument
     */
    public String build(Device device) {
        return String.format(
                "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],"
                        + "\"id\":\"%s\","
                        + "\"publicKey\":\"%s\","
                        + "\"verificationMethod\":[{\"id\":\"%s#key-1\",\"type\":\"Ed25519VerificationKey2020\","
                        + "\"controller\":\"%s\",\"publicKeyBase32\":\"%s\"}],"
                        + "\"authentication\":[\"%s#key-1\"],"
                        + "\"assertionMethod\":[\"%s#key-1\"]}",
                safe(device.getDid()),
                safe(device.getPublicKey()),
                safe(device.getDid()),
                safe(device.getDid()),
                safe(device.getPublicKey()),
                safe(device.getDid()),
                safe(device.getDid())
        );
    }

    private String safe(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
