package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.exception.InvalidSignatureException;
import com.iotauth.iot_auth.util.CryptoUtils;
import com.iotauth.iot_auth.util.DataIntegrity;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.beans.factory.annotation.Value;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class VpVerificationService {

    private final ObjectMapper objectMapper;

    @Value("${iot.auth.vp-domain:iot-auth-backend}")
    private String expectedDomain;

    /** Valeur du champ "domain" que la preuve de la VP doit porter (publiee dans la reponse au challenge). */
    public String getExpectedDomain() {
        return expectedDomain;
    }

    /**
     * Verifie une Verifiable Presentation (VC Data Model 2.0) protegee par une preuve Data Integrity
     * {@code eddsa-jcs-2022} : proofPurpose {@code authentication}, verificationMethod {@code {holderDid}#key-1},
     * {@code challenge} egal au nonce emis par le serveur, {@code domain} egal au domaine attendu.
     * <p>
     * La fraicheur et la liaison au verificateur sont donc portees par la preuve elle-meme (elles sont
     * signees avec le document), et non plus par une signature separee sur "challenge + VP".
     *
     * @param verifiablePresentation JSON de la VP, preuve incluse
     * @param challenge              nonce emis par le serveur pour cette session de renouvellement
     * @param holderDid              DID du dispositif authentifie
     * @param publicKeyBase32        cle publique du dispositif en Base32
     * @return true si la structure et la preuve sont valides
     */
    public boolean verifyPresentation(
            String verifiablePresentation,
            String challenge,
            String holderDid,
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
            Map<String, Object> vp = objectMapper.readValue(verifiablePresentation, new TypeReference<Map<String, Object>>() {});
            Object context = vp.get("@context");
            Object type = vp.get("type");
            if (!(context instanceof List<?> c) || c.isEmpty() || !VcService.VC_CONTEXT_V2.equals(c.get(0))
                    || !(type instanceof List<?> t) || !t.contains("VerifiablePresentation")) {
                log.warn("Structure de VP non conforme (VC Data Model 2.0)");
                return false;
            }
            if (!holderDid.equals(vp.get("holder"))) {
                log.warn("holder de la VP different du DID authentifie");
                return false;
            }
            byte[] publicKey = CryptoUtils.decodeBase32(publicKeyBase32);
            DataIntegrity.verify(
                    vp,
                    (data, signature) -> CryptoUtils.verifyEd25519Bytes(publicKey, data, signature),
                    "authentication",
                    holderDid + "#key-1",
                    challenge,
                    expectedDomain);
            return true;
        } catch (DataIntegrity.ProofException e) {
            log.warn("Echec de verification de la preuve de la VP : {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Erreur lors de la verification de la VP: {}", e.getMessage(), e);
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
    /**
     * Vérifie que le VC contenu dans la VP est exactement le VC émis et signé par
     * l'Issuer (celui conservé en base). Sans ce contrôle, seul l'identifiant du VC
     * était lu dans la VP : le contenu présenté n'était jamais vérifié.
     * <p>
     * La comparaison est structurelle (arbre JSON), donc insensible à l'ordre des
     * champs et aux espaces. Une VP qui ne contient qu'un identifiant, ou un VC
     * modifié (permissions, sujet, dates, preuve), est refusée.
     *
     * @param verifiablePresentation VP JSON reçue du dispositif
     * @param storedRawCredential    VC JSON signé, tel que stocké par l'Issuer
     * @return true si le premier VC de la VP est identique au VC stocké
     */
    public boolean presentedCredentialMatches(String verifiablePresentation, String storedRawCredential) {
        if (verifiablePresentation == null || storedRawCredential == null) {
            return false;
        }
        try {
            JsonNode vpNode = objectMapper.readTree(verifiablePresentation);
            JsonNode vcArray = vpNode.get("verifiableCredential");
            if (vcArray == null || !vcArray.isArray() || vcArray.size() != 1) {
                return false;
            }
            JsonNode presented = vcArray.get(0);
            if (!presented.isObject()) {
                return false;
            }
            return presented.equals(objectMapper.readTree(storedRawCredential));
        } catch (IOException e) {
            log.warn("Comparaison VC présenté / VC stocké impossible: {}", e.getMessage());
            return false;
        }
    }

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
