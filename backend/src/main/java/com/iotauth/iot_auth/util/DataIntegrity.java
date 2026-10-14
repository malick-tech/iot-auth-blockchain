package com.iotauth.iot_auth.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Preuve W3C Data Integrity, suite {@code eddsa-jcs-2022} (Data Integrity EdDSA Cryptosuites v1.0,
 * section 3.3) : donnees signees = SHA-256(JCS(options de preuve)) || SHA-256(JCS(document sans preuve)),
 * signature Ed25519 pure, proofValue en multibase base58btc.
 *
 * La classe ne manipule que des arbres Map/List (convertis par l'appelant depuis Jackson) et ne depend
 * d'aucune bibliotheque : la signature et la verification sont fournies par l'appelant.
 */
public final class DataIntegrity {

    public static final String PROOF_TYPE = "DataIntegrityProof";
    public static final String CRYPTOSUITE = "eddsa-jcs-2022";

    private DataIntegrity() {
    }

    @FunctionalInterface
    public interface Signer {
        byte[] sign(byte[] data);
    }

    @FunctionalInterface
    public interface Verifier {
        boolean verify(byte[] data, byte[] signature);
    }

    public static class ProofException extends Exception {
        public ProofException(String message) {
            super(message);
        }
    }

    /** Retourne une copie du document avec un champ {@code proof}. {@code created} : dateTimeStamp avec fuseau. */
    public static Map<String, Object> addProof(
            Map<String, Object> unsecured,
            Signer signer,
            String verificationMethod,
            String proofPurpose,
            String created,
            String challenge,
            String domain
    ) {
        if (unsecured.containsKey("proof")) {
            throw new IllegalArgumentException("Le document contient deja une preuve");
        }
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("type", PROOF_TYPE);
        options.put("cryptosuite", CRYPTOSUITE);
        options.put("created", created);
        options.put("verificationMethod", verificationMethod);
        options.put("proofPurpose", proofPurpose);
        if (challenge != null) {
            options.put("challenge", challenge);
        }
        if (domain != null) {
            options.put("domain", domain);
        }
        if (unsecured.containsKey("@context")) {
            options.put("@context", unsecured.get("@context"));
        }
        byte[] signature = signer.sign(hashData(options, unsecured));
        Map<String, Object> proof = new LinkedHashMap<>(options);
        proof.put("proofValue", Multibase.toMultibaseBase58btc(signature));
        Map<String, Object> secured = new LinkedHashMap<>(unsecured);
        secured.put("proof", proof);
        return secured;
    }

    /**
     * Verifie la preuve. Tous les attendus sont obligatoires sauf challenge et domain (null = non controle,
     * a reserver aux credentials ; une presentation d'authentification les impose).
     */
    @SuppressWarnings("unchecked")
    public static void verify(
            Map<String, Object> secured,
            Verifier verifier,
            String expectedPurpose,
            String expectedVerificationMethod,
            String expectedChallenge,
            String expectedDomain
    ) throws ProofException {
        Object proofObj = secured.get("proof");
        if (!(proofObj instanceof Map)) {
            throw new ProofException("proof absente ou multiple");
        }
        Map<String, Object> proof = (Map<String, Object>) proofObj;
        if (!PROOF_TYPE.equals(proof.get("type")) || !CRYPTOSUITE.equals(proof.get("cryptosuite"))) {
            throw new ProofException("Suite de preuve non prise en charge");
        }
        if (!expectedPurpose.equals(proof.get("proofPurpose"))) {
            throw new ProofException("proofPurpose inattendu");
        }
        if (!expectedVerificationMethod.equals(proof.get("verificationMethod"))) {
            throw new ProofException("verificationMethod inattendu");
        }
        if (expectedChallenge != null && !expectedChallenge.equals(proof.get("challenge"))) {
            throw new ProofException("challenge inattendu");
        }
        if (expectedDomain != null && !expectedDomain.equals(proof.get("domain"))) {
            throw new ProofException("domain inattendu");
        }
        if (!(proof.get("proofValue") instanceof String proofValue)) {
            throw new ProofException("proofValue absente");
        }
        byte[] signature;
        try {
            signature = Multibase.fromMultibaseBase58btc(proofValue);
        } catch (IllegalArgumentException e) {
            throw new ProofException(e.getMessage());
        }
        if (signature.length != 64) {
            throw new ProofException("Signature de 64 octets attendue");
        }

        Map<String, Object> options = new LinkedHashMap<>(proof);
        options.remove("proofValue");
        Map<String, Object> unsecured = new LinkedHashMap<>(secured);
        unsecured.remove("proof");
        if (options.containsKey("@context")) {
            // La specification exige que le contexte du document COMMENCE par celui de la preuve.
            // Profil du projet, plus strict : egalite exacte, pour qu'aucun contexte (donc aucun terme)
            // ne puisse etre ajoute apres signature.
            if (!contextEquals(unsecured.get("@context"), options.get("@context"))) {
                throw new ProofException("@context du document different de celui de la preuve");
            }
            unsecured.put("@context", options.get("@context"));
        }
        boolean ok;
        try {
            ok = verifier.verify(hashData(options, unsecured), signature);
        } catch (RuntimeException e) {
            throw new ProofException("Signature invalide");
        }
        if (!ok) {
            throw new ProofException("Signature invalide");
        }
    }

    private static boolean contextEquals(Object a, Object b) {
        List<?> la = a instanceof List<?> l ? l : java.util.Collections.singletonList(a);
        List<?> lb = b instanceof List<?> l ? l : java.util.Collections.singletonList(b);
        return la.equals(lb);
    }

    static byte[] hashData(Map<String, Object> options, Map<String, Object> unsecured) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h1 = md.digest(Jcs.canonicalize(options));
            byte[] h2 = md.digest(Jcs.canonicalize(unsecured));
            byte[] out = new byte[64];
            System.arraycopy(h1, 0, out, 0, 32);
            System.arraycopy(h2, 0, out, 32, 32);
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
