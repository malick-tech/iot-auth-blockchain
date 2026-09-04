package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.exception.InvalidSignatureException;
import com.iotauth.iot_auth.util.CryptoUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Slf4j
@Service
@RequiredArgsConstructor
public class VpVerificationService {

    private final ObjectMapper objectMapper;

    /**
     * Vérifie une Verifiable Presentation en validant sa signature Ed25519.
     *
     * Le nonce (challenge) est concaténé au contenu de la VP avant vérification
     * de signature : cela garantit la fraîcheur de la preuve de possession
     * (le dispositif ne peut pas rejouer une VP+signature interceptées sans
     * connaître le nonce courant émis par le serveur).
     *
     * @param verifiablePresentation JSON de la VP
     * @param challenge              nonce émis par le serveur pour cette session de renouvellement
     * @param signature              signature Ed25519 en Base64 sur (challenge + verifiablePresentation)
     * @param publicKeyBase32        clé publique du dispositif en Base32
     * @return true si la signature est valide
     */
    public boolean verifyPresentation(
            String verifiablePresentation,
            String challenge,
            String signature,
            String publicKeyBase32
    ) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            log.warn("La VP est nulle ou vide");
            return false;
        }
        if (challenge == null || challenge.isBlank()) {
            log.warn("Le challenge (nonce) est nul ou vide");
            return false;
        }

        try {
            // Vérification de signature Ed25519 sur challenge || VP
            String signedMessage = challenge + verifiablePresentation;
            boolean isValid = CryptoUtils.verifyEd25519(
                    publicKeyBase32,
                    signedMessage,
                    signature
            );

            if (!isValid) {
                log.warn("Echec de vérification de la signature VP");
            }

            return isValid;
        } catch (Exception e) {
            log.error("Erreur lors de la vérification de la VP: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Extrait l'identifiant du Verifiable Credential depuis une Verifiable Presentation.
     *
     * Structure attendue de la VP :
     * <pre>
     * {
     *   "verifiableCredential": [
     *     { "id": "vc-id-here", ... }
     *   ]
     * }
     * </pre>
     *
     * @param verifiablePresentation JSON de la VP
     * @return identifiant du VC extrait
     * @throws InvalidSignatureException si l'identifiant ne peut pas être extrait
     */
    public String extractVcIdFromPresentation(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            throw new InvalidSignatureException("La VP est nulle ou vide");
        }

        try {
            JsonNode vpNode = objectMapper.readTree(verifiablePresentation);

            // Recherche du VC ID dans les emplacements possibles
            if (vpNode.has("verifiableCredential")) {
                JsonNode vcArray = vpNode.get("verifiableCredential");
                if (vcArray.isArray() && vcArray.size() > 0) {
                    JsonNode vc = vcArray.get(0);
                    if (vc.has("id")) {
                        return vc.get("id").asText();
                    }
                    // Fallback : essayer vcId
                    if (vc.has("vcId")) {
                        return vc.get("vcId").asText();
                    }
                }
            }

            // Fallback : vcId direct sur la VP
            if (vpNode.has("vcId")) {
                return vpNode.get("vcId").asText();
            }

            // Fallback : credentialId
            if (vpNode.has("credentialId")) {
                return vpNode.get("credentialId").asText();
            }

            throw new InvalidSignatureException("Impossible d'extraire l'identifiant VC de la VP");
        } catch (IOException e) {
            log.error("Erreur lors du parsing JSON de la VP: {}", e.getMessage(), e);
            throw new InvalidSignatureException("Format JSON de VP invalide: " + e.getMessage());
        }
    }

    /**
     * Valide la structure d'une Verifiable Presentation.
     * Vérifie les champs requis selon la spécification W3C VC.
     *
     * @param verifiablePresentation JSON de la VP
     * @return true si la structure est valide
     */
    public boolean isValidPresentationStructure(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            return false;
        }

        try {
            JsonNode vpNode = objectMapper.readTree(verifiablePresentation);

            // Champs requis selon la spécification W3C VP
            boolean hasContext = vpNode.has("@context");
            boolean hasType = vpNode.has("type");
            boolean hasProof = vpNode.has("proof");
            boolean hasCredentials = vpNode.has("verifiableCredential");

            return hasContext && hasType && hasProof && hasCredentials;
        } catch (IOException e) {
            log.error("Erreur lors de la validation de la structure VP: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extrait le DID de l'émetteur (issuer) d'un VC contenu dans une VP.
     *
     * @param verifiablePresentation JSON de la VP
     * @return DID de l'émetteur
     * @throws InvalidSignatureException si l'émetteur ne peut pas être extrait
     */
    public String extractIssuerFromPresentation(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            throw new InvalidSignatureException("La VP est nulle ou vide");
        }

        try {
            JsonNode vpNode = objectMapper.readTree(verifiablePresentation);

            if (vpNode.has("verifiableCredential")) {
                JsonNode vcArray = vpNode.get("verifiableCredential");
                if (vcArray.isArray() && vcArray.size() > 0) {
                    JsonNode vc = vcArray.get(0);
                    if (vc.has("issuer")) {
                        return vc.get("issuer").asText();
                    }
                }
            }

            throw new InvalidSignatureException("Impossible d'extraire l'émetteur de la VP");
        } catch (IOException e) {
            log.error("Erreur lors de l'extraction de l'émetteur: {}", e.getMessage(), e);
            throw new InvalidSignatureException("JSON VP invalide: " + e.getMessage());
        }
    }

    /**
     * Extrait le DID du sujet (credential subject) d'un VC contenu dans une VP.
     *
     * @param verifiablePresentation JSON de la VP
     * @return DID du sujet
     * @throws InvalidSignatureException si le sujet ne peut pas être extrait
     */
    public String extractSubjectFromPresentation(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            throw new InvalidSignatureException("La VP est nulle ou vide");
        }

        try {
            JsonNode vpNode = objectMapper.readTree(verifiablePresentation);

            if (vpNode.has("verifiableCredential")) {
                JsonNode vcArray = vpNode.get("verifiableCredential");
                if (vcArray.isArray() && vcArray.size() > 0) {
                    JsonNode vc = vcArray.get(0);
                    if (vc.has("credentialSubject")) {
                        JsonNode subject = vc.get("credentialSubject");
                        if (subject.has("id")) {
                            return subject.get("id").asText();
                        }
                    }
                }
            }

            throw new InvalidSignatureException("Impossible d'extraire le sujet de la VP");
        } catch (IOException e) {
            log.error("Erreur lors de l'extraction du sujet: {}", e.getMessage(), e);
            throw new InvalidSignatureException("JSON VP invalide: " + e.getMessage());
        }
    }
}
