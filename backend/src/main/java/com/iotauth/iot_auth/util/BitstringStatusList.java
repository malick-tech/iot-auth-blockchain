package com.iotauth.iot_auth.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Bitstring Status List v1.0 (W3C) : sequence de bits, le bit d'index 0 etant le bit de poids fort
 * du premier octet ; encodage = GZIP puis multibase base64url sans remplissage (prefixe 'u').
 */
public final class BitstringStatusList {

    /** Taille minimale recommandee par la specification (confidentialite de groupe). */
    public static final int MIN_SIZE_BITS = 131_072;

    private final byte[] bits;

    public BitstringStatusList(int sizeBits) {
        if (sizeBits < MIN_SIZE_BITS || sizeBits % 8 != 0) {
            throw new IllegalArgumentException("Taille de liste invalide (minimum 131072 bits, multiple de 8)");
        }
        this.bits = new byte[sizeBits / 8];
    }

    private BitstringStatusList(byte[] bits) {
        this.bits = bits;
    }

    public int sizeBits() {
        return bits.length * 8;
    }

    public void set(int index, boolean value) {
        check(index);
        int mask = 0x80 >> (index % 8);
        if (value) {
            bits[index / 8] |= (byte) mask;
        } else {
            bits[index / 8] &= (byte) ~mask;
        }
    }

    public boolean get(int index) {
        check(index);
        return (bits[index / 8] & (0x80 >> (index % 8))) != 0;
    }

    private void check(int index) {
        if (index < 0 || index >= sizeBits()) {
            throw new IllegalArgumentException("Index hors de la liste de statuts : " + index);
        }
    }

    public String encode() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
                gz.write(bits);
            }
            return Multibase.toMultibaseBase64Url(bos.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static BitstringStatusList decode(String encodedList) {
        try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(Multibase.fromMultibaseBase64Url(encodedList)))) {
            byte[] raw = gz.readAllBytes();
            if (raw.length * 8 < MIN_SIZE_BITS) {
                throw new IllegalArgumentException("Liste de statuts trop courte");
            }
            return new BitstringStatusList(raw);
        } catch (IOException e) {
            throw new IllegalArgumentException("encodedList invalide", e);
        }
    }
}
