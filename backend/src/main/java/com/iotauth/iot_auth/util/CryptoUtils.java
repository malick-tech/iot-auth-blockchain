package com.iotauth.iot_auth.util;

import com.iotauth.iot_auth.exception.InvalidSignatureException;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

public final class CryptoUtils {

    private static final String DID_PREFIX = "did:algo:";
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int[] BASE32_LOOKUP = new int[256];

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        Arrays.fill(BASE32_LOOKUP, -1);
        for (int i = 0; i < BASE32_CHARS.length(); i++) {
            BASE32_LOOKUP[BASE32_CHARS.charAt(i)] = i;
        }
    }

    private CryptoUtils() {
    }

    public static boolean verifyEd25519(String publicKeyBase32, String message, String signatureBase64) {
        if (message == null) {
            throw new InvalidSignatureException("Le message a verifier ne peut pas etre null");
        }
        return verifyEd25519(publicKeyBase32, message.getBytes(StandardCharsets.UTF_8), signatureBase64);
    }

    public static boolean verifyEd25519(String publicKeyBase32, byte[] data, String signatureBase64) {
        if (data == null) {
            throw new InvalidSignatureException("Les donnees a verifier ne peuvent pas etre null");
        }

        try {
            byte[] publicKeyBytes = decodeBase32(publicKeyBase32);
            byte[] signatureBytes = decodeBase64(signatureBase64);
            return verifyEd25519Bytes(publicKeyBytes, data, signatureBytes);
        } catch (IllegalArgumentException e) {
            throw new InvalidSignatureException("Encodage invalide (cle ou signature) : " + e.getMessage(), e);
        }
    }

    public static boolean verifyEd25519Bytes(byte[] publicKeyBytes, byte[] message, byte[] signature) {
        validatePublicKey(publicKeyBytes);
        validateSignature(signature);

        if (message == null) {
            throw new InvalidSignatureException("Le message a verifier ne peut pas etre null");
        }

        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, publicKey);
        signer.update(message, 0, message.length);
        return signer.verifySignature(signature);
    }

    public static String signEd25519(byte[] privateKeyBytes, String message) {
        if (message == null) {
            throw new IllegalArgumentException("Le message a signer ne peut pas etre null");
        }
        return encodeBase64(signEd25519Bytes(privateKeyBytes, message.getBytes(StandardCharsets.UTF_8)));
    }

    public static byte[] signEd25519Bytes(byte[] privateKeyBytes, byte[] message) {
        validatePrivateKey(privateKeyBytes);
        if (message == null) {
            throw new IllegalArgumentException("Le message a signer ne peut pas etre null");
        }

        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

   public static byte[] generateEd25519PrivateKeyBytes() {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        return privateKey;
    }

    private static final SecureRandom NONCE_RANDOM = new SecureRandom();

    /**
     * Génère un nonce à usage unique de 32 octets (challenge-response,
     * renouvellement JWT PoP via VP), encodé en Base64 URL sans padding.
     */
    public static String generateNonce() {
        byte[] bytes = new byte[32];
        NONCE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] deriveEd25519PublicKeyBytes(byte[] privateKeyBytes) {
        validatePrivateKey(privateKeyBytes);
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        return privateKey.generatePublicKey().getEncoded();
    }

    public static boolean validateDidFormat(String did, String publicKeyBase32) {
        if (isBlank(did) || isBlank(publicKeyBase32)) {
            return false;
        }
        return buildDid(publicKeyBase32).equalsIgnoreCase(did);
    }

    public static boolean validateDidFormat(String did, String publicKeyBase32, long appId, String network) {
        if (isBlank(did) || isBlank(publicKeyBase32)) {
            return false;
        }
        return buildDid(publicKeyBase32, appId, network).equalsIgnoreCase(did);
    }

    public static String buildDid(String publicKeyBase32) {
        if (isBlank(publicKeyBase32)) {
            throw new IllegalArgumentException("La cle publique ne peut pas etre vide");
        }
        return DID_PREFIX + publicKeyBase32.toUpperCase();
    }

    public static String buildDid(String publicKeyBase32, long appId, String network) {
        byte[] publicKeyBytes = decodeBase32(publicKeyBase32);
        validatePublicKey(publicKeyBytes);

        String normalizedNetwork = normalizeDidNetwork(network);
        String networkSegment = "mainnet".equals(normalizedNetwork) ? "" : normalizedNetwork + ":";
        return DID_PREFIX + networkSegment + "app:" + appId + ":" + encodeHex(publicKeyBytes);
    }

    public static byte[] extractDidSubjectPublicKey(String did) {
        if (isBlank(did)) {
            throw new IllegalArgumentException("Le DID ne peut pas etre vide");
        }

        String[] parts = did.split(":");
        boolean hasNetwork = parts.length == 6;
        boolean noNetwork = parts.length == 5;
        if (!hasNetwork && !noNetwork) {
            throw new IllegalArgumentException("Format did:algo invalide : " + did);
        }
        if (!"did".equals(parts[0]) || !"algo".equals(parts[1])) {
            throw new IllegalArgumentException("Le DID doit commencer par did:algo");
        }

        int appIndex = hasNetwork ? 3 : 2;
        int keyIndex = hasNetwork ? 5 : 4;
        if (!"app".equals(parts[appIndex])) {
            throw new IllegalArgumentException("Namespace did:algo non supporte : " + did);
        }

        byte[] publicKeyBytes = decodeHex(parts[keyIndex]);
        validatePublicKey(publicKeyBytes);
        return publicKeyBytes;
    }

    public static byte[] deriveDidDataBoxKey(byte[] publicKeyBytes) {
        validatePublicKey(publicKeyBytes);
        return Arrays.copyOf(hashSha256Bytes(publicKeyBytes), 8);
    }

    // ============= Hashing for Replay Prevention =============

    /**
     * Computes SHA-256 hash of a Verifiable Presentation.
     * Used for replay prevention - each VP is hashed and checked if already used.
     *
     * @param vp Verifiable Presentation (JSON string or raw VP)
     * @return Base64-encoded SHA-256 hash of the VP
     */
    public static String hashVp(String vp) {
        if (isBlank(vp)) {
            throw new IllegalArgumentException("VP ne peut pas etre vide");
        }
        return hashSha256(vp.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes SHA-256 hash of arbitrary data.
     *
     * @param data Data to hash
     * @return Base64-encoded SHA-256 hash
     */
    public static String hashSha256(byte[] data) {
        return encodeBase64(hashSha256Bytes(data));
    }

    /**
     * Comme hashSha256, mais retourne les octets bruts (utile pour construire
     * des noms de box Algorand, qui doivent être des byte[], pas du texte encodé).
     */
    public static byte[] hashSha256Bytes(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Les donnees a hasher ne peuvent pas etre null");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    // ============= Base32 Encoding/Decoding =============

    public static String encodeBase32(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Les donnees Base32 ne peuvent pas etre null");
        }

        int outputLength = (data.length * 8 + 4) / 5;
        char[] result = new char[outputLength];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;

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

        return new String(result);
    }

    public static byte[] decodeBase32(String base32) {
        if (isBlank(base32)) {
            throw new IllegalArgumentException("La valeur Base32 ne peut pas etre vide");
        }
        return base32Decode(base32.toUpperCase().replace("=", ""));
    }

    // ============= Base64 Encoding/Decoding =============

    public static String encodeBase64(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Les donnees Base64 ne peuvent pas etre null");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] decodeBase64(String base64) {
        if (isBlank(base64)) {
            throw new IllegalArgumentException("La valeur Base64 ne peut pas etre vide");
        }
        return Base64.getUrlDecoder().decode(base64);
    }

    public static String encodeBase64Standard(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Les donnees Base64 ne peuvent pas etre null");
        }
        return Base64.getEncoder().encodeToString(data);
    }

    public static String encodeHex(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Les donnees hex ne peuvent pas etre null");
        }
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte b : data) {
            builder.append(String.format("%02x", b & 0xFF));
        }
        return builder.toString();
    }

    public static byte[] decodeHex(String hex) {
        if (isBlank(hex) || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("La valeur hex est invalide");
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Caractere hex invalide");
            }
            result[i / 2] = (byte) ((high << 4) + low);
        }
        return result;
    }

    // ============= Private Helpers =============

    private static byte[] base32Decode(String base32) {
        int outputLength = base32.length() * 5 / 8;
        byte[] result = new byte[outputLength];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;

        for (char c : base32.toCharArray()) {
            if (c >= BASE32_LOOKUP.length || BASE32_LOOKUP[c] < 0) {
                throw new IllegalArgumentException("Caractere Base32 invalide : " + c);
            }
            buffer = (buffer << 5) | BASE32_LOOKUP[c];
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                result[index++] = (byte) ((buffer >> bitsLeft) & 0xFF);
            }
        }

        return result;
    }

    private static void validatePrivateKey(byte[] privateKeyBytes) {
        if (privateKeyBytes == null || privateKeyBytes.length != 32) {
            int length = privateKeyBytes == null ? 0 : privateKeyBytes.length;
            throw new IllegalArgumentException("Clé privée Ed25519 invalide : longueur=" + length + " (attendu 32)");
        }
    }

    private static void validatePublicKey(byte[] publicKeyBytes) {
        if (publicKeyBytes == null || publicKeyBytes.length != 32) {
            int length = publicKeyBytes == null ? 0 : publicKeyBytes.length;
            throw new InvalidSignatureException("Clé publique Ed25519 invalide : longueur=" + length + " (attendu 32)");
        }
    }

    private static void validateSignature(byte[] signature) {
        if (signature == null || signature.length != 64) {
            int length = signature == null ? 0 : signature.length;
            throw new InvalidSignatureException("Signature Ed25519 invalide : longueur=" + length + " (attendu 64)");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String normalizeDidNetwork(String network) {
        if (isBlank(network) || "mainnet".equalsIgnoreCase(network)) {
            return "mainnet";
        }
        if ("localnet".equalsIgnoreCase(network)) {
            return "custom";
        }
        return network.toLowerCase();
    }
}
