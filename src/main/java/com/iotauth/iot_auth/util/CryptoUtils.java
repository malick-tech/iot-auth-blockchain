package com.iotauth.iot_auth.util;

import com.iotauth.iot_auth.exception.InvalidSignatureException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.Base64;

/**
 * Utilitaires cryptographiques pour le système d'authentification IoT.
 *
 * Algorithme : Ed25519 (Edwards-curve Digital Signature Algorithm)
 * Bibliothèque : BouncyCastle
 *
 * Conventions d'encodage :
 * - Clés publiques  → Base32 (compatible Algorand / format DID)
 * - Signatures      → Base64 URL-safe sans padding
 * - Nonces          → Base64 URL-safe sans padding
 *
 * Toutes les méthodes sont statiques (pas d'état mutable).
 */
@Slf4j
public class CryptoUtils {

    static {
        // Enregistrer BouncyCastle comme provider JCA une seule fois
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CryptoUtils() {
        // Classe utilitaire — pas d'instanciation
    }

    // ════════════════════════════════════════════════════════════
    // VÉRIFICATION DE SIGNATURE Ed25519
    // ════════════════════════════════════════════════════════════

    /**
     * Vérifie une signature Ed25519.
     *
     * @param publicKeyBase32 Clé publique Ed25519 encodée en Base32 (32 octets)
     * @param message         Message signé (texte brut ou concaténation de champs)
     * @param signatureBase64 Signature encodée en Base64 URL-safe (64 octets)
     * @return true si la signature est valide
     * @throws InvalidSignatureException si la clé ou la signature sont malformées
     */
    public static boolean verifyEd25519(String publicKeyBase32,
                                        String message,
                                        String signatureBase64) {
        try {
            byte[] pubKeyBytes  = decodeBase32(publicKeyBase32);
            byte[] sigBytes     = decodeBase64(signatureBase64);
            byte[] messageBytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            return verifyEd25519Bytes(pubKeyBytes, messageBytes, sigBytes);

        } catch (IllegalArgumentException e) {
            throw new InvalidSignatureException(
                    "Encodage invalide (clé ou signature) : " + e.getMessage(), e);
        }
    }

    /**
     * Variante : vérifie une signature sur des données binaires.
     *
     * @param publicKeyBase32 Clé publique en Base32
     * @param data            Données binaires signées
     * @param signatureBase64 Signature en Base64 URL-safe
     */
    public static boolean verifyEd25519(String publicKeyBase32,
                                        byte[] data,
                                        String signatureBase64) {
        try {
            byte[] pubKeyBytes = decodeBase32(publicKeyBase32);
            byte[] sigBytes    = decodeBase64(signatureBase64);
            return verifyEd25519Bytes(pubKeyBytes, data, sigBytes);
        } catch (IllegalArgumentException e) {
            throw new InvalidSignatureException(
                    "Encodage invalide (clé ou signature) : " + e.getMessage(), e);
        }
    }

    /**
     * Noyau de vérification — opère directement sur des tableaux d'octets.
     */
    public static boolean verifyEd25519Bytes(byte[] publicKeyBytes,
                                             byte[] message,
                                             byte[] signature) {
        if (publicKeyBytes.length != 32) {
            throw new InvalidSignatureException(
                    "Clé publique Ed25519 invalide : longueur=" + publicKeyBytes.length + " (attendu 32)");
        }
        if (signature.length != 64) {
            throw new InvalidSignatureException(
                    "Signature Ed25519 invalide : longueur=" + signature.length + " (attendu 64)");
        }

        Ed25519PublicKeyParameters pubKey =
                new Ed25519PublicKeyParameters(publicKeyBytes, 0);

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, pubKey);         // false = mode vérification
        signer.update(message, 0, message.length);

        return signer.verifySignature(signature);
    }

    // ════════════════════════════════════════════════════════════
    // SIGNATURE Ed25519 (côté Spring Boot - Issuer)
    // ════════════════════════════════════════════════════════════

    /**
     * Signe un message avec une clé privée Ed25519.
     * Utilisé par Spring Boot pour signer les VCs et les JWT PoP.
     *
     * @param privateKeyBytes Clé privée Ed25519 (32 octets)
     * @param message         Message à signer (UTF-8)
     * @return Signature en Base64 URL-safe sans padding
     */
    public static String signEd25519(byte[] privateKeyBytes, String message) {
        byte[] messageBytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature    = signEd25519Bytes(privateKeyBytes, messageBytes);
        return encodeBase64(signature);
    }

    /**
     * Noyau de signature — opère directement sur des tableaux d'octets.
     */
    public static byte[] signEd25519Bytes(byte[] privateKeyBytes, byte[] message) {
        if (privateKeyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "Clé privée Ed25519 invalide : longueur=" + privateKeyBytes.length);
        }

        Ed25519PrivateKeyParameters privKey =
                new Ed25519PrivateKeyParameters(privateKeyBytes, 0);

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privKey);          // true = mode signature
        signer.update(message, 0, message.length);

        return signer.generateSignature();
    }

    // ════════════════════════════════════════════════════════════
    // VALIDATION DU FORMAT DID
    // ════════════════════════════════════════════════════════════

    /**
     * Vérifie que le DID est cohérent avec la clé publique.
     *
     * Format attendu : "did:algo:" + Base32(Kpub_Ed25519)
     * C'est le même format qu'une adresse Algorand (sans le checksum).
     *
     * @param did       DID déclaré par le device
     * @param publicKeyBase32 Clé publique déclarée par le device
     * @return true si DID == "did:algo:" + publicKeyBase32
     */
    public static boolean validateDidFormat(String did, String publicKeyBase32) {
        if (did == null || publicKeyBase32 == null) return false;

        String expectedDid = "did:algo:" + publicKeyBase32.toUpperCase();
        return expectedDid.equals(did.toUpperCase());
    }

    /**
     * Construit un DID Algorand à partir d'une clé publique Base32.
     *
     * @param publicKeyBase32 Clé publique Ed25519 en Base32
     * @return DID complet : "did:algo:{publicKeyBase32}"
     */
    public static String buildDid(String publicKeyBase32) {
        return "did:algo:" + publicKeyBase32.toUpperCase();
    }

    // ════════════════════════════════════════════════════════════
    // UTILITAIRES D'ENCODAGE
    // ════════════════════════════════════════════════════════════

    /**
     * Encode des octets en Base32 (alphabet Algorand / RFC 4648).
     */
    public static String encodeBase32(byte[] data) {
        return new String(BASE32_ALPHABET_ENCODE(data));
    }

    /**
     * Décode une chaîne Base32 en octets.
     */
    public static byte[] decodeBase32(String base32) {
        // Utilise le décodeur Base32 intégré à Algorand SDK
        // (com.algorand.algosdk.util.Encoder.decodeToMsgPack est privé,
        //  on implémente directement RFC 4648 sans padding)
        return base32Decode(base32.toUpperCase().replaceAll("=", ""));
    }

    /**
     * Encode des octets en Base64 URL-safe sans padding.
     */
    public static String encodeBase64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Décode une chaîne Base64 URL-safe en octets.
     */
    public static byte[] decodeBase64(String base64) {
        return Base64.getUrlDecoder().decode(base64);
    }

    /**
     * Encode des octets en Base64 standard (pour les VCs W3C).
     */
    public static String encodeBase64Standard(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    // ════════════════════════════════════════════════════════════
    // IMPLÉMENTATION BASE32 RFC 4648 (sans dépendance externe)
    // ════════════════════════════════════════════════════════════

    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int[]  BASE32_LOOKUP;

    static {
        BASE32_LOOKUP = new int[256];
        java.util.Arrays.fill(BASE32_LOOKUP, -1);
        for (int i = 0; i < BASE32_CHARS.length(); i++) {
            BASE32_LOOKUP[BASE32_CHARS.charAt(i)] = i;
        }
    }

    private static char[] BASE32_ALPHABET_ENCODE(byte[] data) {
        int outputLength = (data.length * 8 + 4) / 5;
        char[] result = new char[outputLength];
        int buffer = 0, bitsLeft = 0, index = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                result[index++] = BASE32_CHARS.charAt((buffer >> bitsLeft) & 31);
            }
        }
        if (bitsLeft > 0) {
            result[index] = BASE32_CHARS.charAt((buffer << (5 - bitsLeft)) & 31);
        }
        return result;
    }

    private static byte[] base32Decode(String base32) {
        int outputLength = base32.length() * 5 / 8;
        byte[] result = new byte[outputLength];
        int buffer = 0, bitsLeft = 0, index = 0;

        for (char c : base32.toCharArray()) {
            int val = BASE32_LOOKUP[c];
            if (val < 0) {
                throw new IllegalArgumentException("Caractère Base32 invalide : " + c);
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                result[index++] = (byte) ((buffer >> bitsLeft) & 0xFF);
            }
        }
        return result;
    }
}
