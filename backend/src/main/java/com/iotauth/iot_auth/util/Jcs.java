package com.iotauth.iot_auth.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Canonicalisation JSON JCS (RFC 8785) sur l'arbre Map / List / String / Boolean / entier / null.
 *
 * Les nombres non entiers sont refuses : leur forme canonique depend de l'algorithme
 * ECMAScript de serialisation des flottants, que ce projet n'utilise pas (les valeurs
 * non entieres doivent etre portees par des chaines). Les entiers au-dela de 2^53-1 sont
 * refuses car non representables de facon interoperable.
 *
 * Le tri des noms de proprietes se fait par unites de code UTF-16, ce que fait
 * String.compareTo en Java (RFC 8785 section 3.2.3).
 */
public final class Jcs {

    private static final BigInteger MAX_SAFE = BigInteger.valueOf((1L << 53) - 1);

    private Jcs() {
    }

    public static byte[] canonicalize(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void write(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof Boolean b) {
            out.append(b ? "true" : "false");
        } else if (value instanceof String s) {
            writeString(s, out);
        } else if (value instanceof Integer || value instanceof Long || value instanceof Short
                || value instanceof Byte || value instanceof BigInteger) {
            BigInteger n = new BigInteger(value.toString());
            if (n.abs().compareTo(MAX_SAFE) > 0) {
                throw new IllegalArgumentException("Entier hors de l'intervalle sur de JSON (2^53-1)");
            }
            out.append(n);
        } else if (value instanceof Number) {
            throw new IllegalArgumentException("Nombre non entier non pris en charge par JCS : utiliser une chaine");
        } else if (value instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                if (!(k instanceof String)) {
                    throw new IllegalArgumentException("Les cles d'objet doivent etre des chaines");
                }
                keys.add((String) k);
            }
            keys.sort(String::compareTo);
            out.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(k, out);
                out.append(':');
                write(map.get(k), out);
            }
            out.append('}');
        } else if (value instanceof Collection<?> c) {
            out.append('[');
            boolean first = true;
            for (Object item : c) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(item, out);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("Type non serialisable en JCS : " + value.getClass().getName());
        }
    }

    private static void writeString(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\t' -> out.append("\\t");
                case '\n' -> out.append("\\n");
                case '\f' -> out.append("\\f");
                case '\r' -> out.append("\\r");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
