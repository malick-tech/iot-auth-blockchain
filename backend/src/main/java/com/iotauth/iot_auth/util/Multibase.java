package com.iotauth.iot_auth.util;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

/**
 * Multibase (base58btc 'z', base64url sans remplissage 'u') et Multikey Ed25519
 * (prefixe multicodec 0xed01), conformement aux specifications W3C Controller Documents
 * et Data Integrity.
 */
public final class Multibase {

    private static final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger FIFTY_EIGHT = BigInteger.valueOf(58);

    private Multibase() {
    }

    public static String encodeBase58btc(byte[] data) {
        BigInteger n = new BigInteger(1, data);
        StringBuilder sb = new StringBuilder();
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(FIFTY_EIGHT);
            sb.append(B58.charAt(qr[1].intValue()));
            n = qr[0];
        }
        for (byte b : data) {
            if (b != 0) {
                break;
            }
            sb.append('1');
        }
        return sb.reverse().toString();
    }

    public static byte[] decodeBase58btc(String text) {
        BigInteger n = BigInteger.ZERO;
        for (int i = 0; i < text.length(); i++) {
            int digit = B58.indexOf(text.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("Caractere base58 invalide");
            }
            n = n.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(digit));
        }
        byte[] body = n.signum() == 0 ? new byte[0] : n.toByteArray();
        if (body.length > 0 && body[0] == 0) {
            body = Arrays.copyOfRange(body, 1, body.length);
        }
        int leadingOnes = 0;
        while (leadingOnes < text.length() && text.charAt(leadingOnes) == '1') {
            leadingOnes++;
        }
        byte[] result = new byte[leadingOnes + body.length];
        System.arraycopy(body, 0, result, leadingOnes, body.length);
        return result;
    }

    public static String toMultibaseBase58btc(byte[] data) {
        return "z" + encodeBase58btc(data);
    }

    public static byte[] fromMultibaseBase58btc(String text) {
        if (text == null || !text.startsWith("z")) {
            throw new IllegalArgumentException("Multibase base58btc attendu (prefixe 'z')");
        }
        return decodeBase58btc(text.substring(1));
    }

    public static String toMultibaseBase64Url(byte[] data) {
        return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] fromMultibaseBase64Url(String text) {
        if (text == null || !text.startsWith("u")) {
            throw new IllegalArgumentException("Multibase base64url attendu (prefixe 'u')");
        }
        return Base64.getUrlDecoder().decode(text.substring(1));
    }

    /** publicKeyMultibase d'une cle Ed25519 : 'z' + base58btc(0xed01 || cle). */
    public static String multikeyEd25519(byte[] publicKey) {
        if (publicKey == null || publicKey.length != 32) {
            throw new IllegalArgumentException("Cle publique Ed25519 de 32 octets attendue");
        }
        byte[] prefixed = new byte[34];
        prefixed[0] = (byte) 0xed;
        prefixed[1] = 0x01;
        System.arraycopy(publicKey, 0, prefixed, 2, 32);
        return toMultibaseBase58btc(prefixed);
    }

    public static byte[] publicKeyFromMultikey(String multibase) {
        byte[] raw = fromMultibaseBase58btc(multibase);
        if (raw.length != 34 || raw[0] != (byte) 0xed || raw[1] != 0x01) {
            throw new IllegalArgumentException("Multikey Ed25519 invalide (prefixe 0xed01 attendu)");
        }
        return Arrays.copyOfRange(raw, 2, 34);
    }
}
