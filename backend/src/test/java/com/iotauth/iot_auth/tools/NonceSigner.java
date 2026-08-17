package com.iotauth.iot_auth.tools;

import com.iotauth.iot_auth.util.CryptoUtils;

import java.util.HexFormat;

/**
 * Signe le nonce retourné par /api/enrollment/first-contact pour simuler
 * la réponse cryptographique d'un device Ed25519.
 *
 * Usage :
 *   ./mvnw -DskipTests test-compile exec:java \
 *     -Dexec.classpathScope=test \
 *     -Dexec.mainClass=com.iotauth.iot_auth.tools.NonceSigner \
 *     -Dexec.args="<DEVICE_PRIVATE_KEY_HEX> <NONCE>"
 */
public final class NonceSigner {

    private NonceSigner() {
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: NonceSigner <DEVICE_PRIVATE_KEY_HEX> <NONCE>");
            System.exit(1);
        }

        byte[] privateKey = HexFormat.of().parseHex(args[0]);
        String nonce = args[1];
        String signedNonce = CryptoUtils.signEd25519(privateKey, nonce);

        System.out.println("signed_nonce=" + signedNonce);
        System.out.println();
        System.out.println("Variable Postman à copier :");
        System.out.println("signed_nonce = " + signedNonce);
    }
}
