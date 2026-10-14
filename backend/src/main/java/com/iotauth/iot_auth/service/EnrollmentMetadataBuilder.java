package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.util.CryptoUtils;
import com.iotauth.iot_auth.util.Multibase;
import org.springframework.stereotype.Component;

/**
 * Construit le DID Document JSON utilisé lors de la publication on-chain (PUBLISH_DID).
 * Extrait de EnrollmentService pour permettre la réutilisation par
 * AlgorandPublishingRecoveryService sans créer de dépendance circulaire.
 */
@Component
public class EnrollmentMetadataBuilder {

    /**
     * Produit le DID Document conforme a W3C DID Core 1.0 (representation JSON-LD) pour la methode
     * did:algo (app namespace) : une methode de verification de type {@code Multikey}
     * ({@code publicKeyMultibase} = 'z' + base58btc(0xed01 || cle Ed25519)), referencee comme
     * {@code authentication} et {@code assertionMethod}.
     * <p>
     * Vie privee : ce document est public et permanent (l'historique de la chaine
     * n'est jamais efface). Il ne contient donc que l'identifiant et la cle publique.
     * Le numero de serie, le type, la localisation et le groupe logique restent
     * dans PostgreSQL et ne doivent jamais etre publies on-chain.
     *
     * @param device le dispositif dont le DID Document doit etre publie
     * @return JSON-LD serialise, pret a etre passe a AlgorandService.publishDidDocument
     */
    public String build(Device device) {
        String did = safe(device.getDid());
        String multikey = Multibase.multikeyEd25519(CryptoUtils.decodeBase32(device.getPublicKey()));
        return String.format(
                "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/multikey/v1\"],"
                        + "\"id\":\"%s\","
                        + "\"verificationMethod\":[{\"id\":\"%s#key-1\",\"type\":\"Multikey\","
                        + "\"controller\":\"%s\",\"publicKeyMultibase\":\"%s\"}],"
                        + "\"authentication\":[\"%s#key-1\"],"
                        + "\"assertionMethod\":[\"%s#key-1\"]}",
                did, did, did, multikey, did, did
        );
    }

    private String safe(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
