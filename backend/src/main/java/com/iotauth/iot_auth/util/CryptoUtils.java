package com.iotauth.iot_auth.util;

import com.iotauth.iot_auth.exception.InvalidSignatureException;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
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

    public static String buildDid(String publicKeyBase32) {
        if (isBlank(publicKeyBase32)) {
            throw new IllegalArgumentException("La cle publique ne peut pas etre vide");
        }
        return DID_PREFIX + publicKeyBase32.toUpperCase();
    }

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
}
