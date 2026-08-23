package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.exception.InvalidSignatureException;
import com.iotauth.iot_auth.util.CryptoUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class VpVerificationService {

    private final ObjectMapper objectMapper;

    /**
     * Verifies a Verifiable Presentation by validating its signature.
     * In a real implementation, this would follow the W3C VP standard.
     *
     * For this prototype, we assume:
     * - VP contains a proof with signature
     * - Signature is Ed25519, computed over (challenge || verifiablePresentation)
     * - Public key is provided separately
     *
     * Le nonce (challenge) est concatÃ©nÃ© au contenu de la VP avant vÃ©rification
     * de signature : cela garantit la fraÃ®cheur de la preuve de possession
     * (le dispositif ne peut pas rejouer une VP+signature interceptÃ©es sans
     * connaÃ®tre le nonce courant Ã©mis par le serveur).
     *
     * @param verifiablePresentation JSON string of VP
     * @param challenge nonce Ã©mis par le serveur pour cette session de renouvellement
     * @param signature Base64-encoded ED25519 signature over (challenge + verifiablePresentation)
     * @param publicKeyBase32 Base32-encoded public key
     * @return true if VP signature is valid
     */
    public boolean verifyPresentation(
            String verifiablePresentation,
            String challenge,
            String signature,
            String publicKeyBase32
    ) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            log.warn("VP is null or blank");
            return false;
        }
        if (challenge == null || challenge.isBlank()) {
            log.warn("Challenge (nonce) is null or blank");
            return false;
        }

        try {
            // In a real implementation, would verify VP according to W3C spec
            // For prototype: Ed25519 signature verification over challenge || VP

            String signedMessage = challenge + verifiablePresentation;
            boolean isValid = CryptoUtils.verifyEd25519(
                    publicKeyBase32,
                    signedMessage,
                    signature
            );

            if (!isValid) {
                log.warn("VP signature verification failed");
            }

            return isValid;
        } catch (Exception e) {
            log.error("Error verifying VP: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Extracts the Verifiable Credential ID from a Verifiable Presentation.
     *
     * Assumes VP is a JSON object with structure:
     * {
     *   "verifiableCredential": [
     *     {
     *       "id": "vc-id-here",
     *       ...
     *     }
     *   ]
     * }
     *
     * @param verifiablePresentation JSON string of VP
     * @return VC ID extracted from VP
     * @throws InvalidSignatureException if VC ID cannot be extracted
     */
    public String extractVcIdFromPresentation(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            throw new InvalidSignatureException("VP is null or blank");
        }

        try {
            JsonNode vpNode = objectMapper.readTree(verifiablePresentation);

            // Try to find VC ID in various possible locations
            if (vpNode.has("verifiableCredential")) {
                JsonNode vcArray = vpNode.get("verifiableCredential");
                if (vcArray.isArray() && vcArray.size() > 0) {
                    JsonNode vc = vcArray.get(0);
                    if (vc.has("id")) {
                        return vc.get("id").asText();
                    }
                    // Fallback: try to find vcId
                    if (vc.has("vcId")) {
                        return vc.get("vcId").asText();
                    }
                }
            }

            // Alternative: try direct vcId
            if (vpNode.has("vcId")) {
                return vpNode.get("vcId").asText();
            }

            // Fallback: try credentialId
            if (vpNode.has("credentialId")) {
                return vpNode.get("credentialId").asText();
            }

            throw new InvalidSignatureException("Could not extract VC ID from VP");
        } catch (IOException e) {
            log.error("Error parsing VP JSON: {}", e.getMessage(), e);
            throw new InvalidSignatureException("Invalid VP JSON format: " + e.getMessage());
        }
    }

    /**
     * Validates the structure of a Verifiable Presentation.
     * Checks required fields according to W3C VC spec.
     *
     * @param verifiablePresentation JSON VP
     * @return true if VP has valid structure
     */
    public boolean isValidPresentationStructure(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            return false;
        }

        try {
            JsonNode vpNode = objectMapper.readTree(verifiablePresentation);

            // Required fields for W3C VP
            boolean hasContext = vpNode.has("@context");
            boolean hasType = vpNode.has("type");
            boolean hasProof = vpNode.has("proof");
            boolean hasCredentials = vpNode.has("verifiableCredential");

            return hasContext && hasType && hasProof && hasCredentials;
        } catch (IOException e) {
            log.error("Error validating VP structure: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts the issuer DID from a Verifiable Credential within a VP.
     *
     * @param verifiablePresentation JSON VP
     * @return Issuer DID
     * @throws InvalidSignatureException if issuer cannot be extracted
     */
    public String extractIssuerFromPresentation(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            throw new InvalidSignatureException("VP is null or blank");
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

            throw new InvalidSignatureException("Could not extract issuer from VP");
        } catch (IOException e) {
            log.error("Error extracting issuer: {}", e.getMessage(), e);
            throw new InvalidSignatureException("Invalid VP JSON: " + e.getMessage());
        }
    }

    /**
     * Extracts the credential subject DID from a VC within a VP.
     *
     * @param verifiablePresentation JSON VP
     * @return Subject DID
     * @throws InvalidSignatureException if subject cannot be extracted
     */
    public String extractSubjectFromPresentation(String verifiablePresentation) {
        if (verifiablePresentation == null || verifiablePresentation.isBlank()) {
            throw new InvalidSignatureException("VP is null or blank");
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

            throw new InvalidSignatureException("Could not extract subject from VP");
        } catch (IOException e) {
            log.error("Error extracting subject: {}", e.getMessage(), e);
            throw new InvalidSignatureException("Invalid VP JSON: " + e.getMessage());
        }
    }
}
