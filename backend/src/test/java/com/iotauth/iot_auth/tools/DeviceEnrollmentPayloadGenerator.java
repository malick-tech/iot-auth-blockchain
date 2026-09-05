package com.iotauth.iot_auth.tools;

import com.iotauth.iot_auth.util.CryptoUtils;

import java.util.HexFormat;

/**
 * Outil local pour simuler un device IoT sans matériel physique.
 *
 * Usage :
 *   ./mvnw -DskipTests test-compile exec:java \
 *     -Dexec.classpathScope=test \
 *     -Dexec.mainClass=com.iotauth.iot_auth.tools.DeviceEnrollmentPayloadGenerator \
    *     -Dexec.args="IOT-DEVICE-001 1014"
 *
 * Ou avec une clé privée fixe en hexadécimal 32 octets :
 *   ./mvnw -DskipTests test-compile exec:java \
 *     -Dexec.classpathScope=test \
 *     -Dexec.mainClass=com.iotauth.iot_auth.tools.DeviceEnrollmentPayloadGenerator \
    *     -Dexec.args="IOT-DEVICE-001 1014 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
 */
public final class DeviceEnrollmentPayloadGenerator {

    private DeviceEnrollmentPayloadGenerator() {
    }

    public static void main(String[] args) {
        String serialNumber = args.length >= 1 ? args[0] : "IOT-DEVICE-001";
        long appId = args.length >= 2 ? Long.parseLong(args[1]) : 1014L;
        byte[] privateKey = args.length >= 3
                ? HexFormat.of().parseHex(args[2])
                : CryptoUtils.generateEd25519PrivateKeyBytes();

        String publicKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(privateKey));
        String did = CryptoUtils.buildDid(publicKey, appId, "localnet");
        String signatureSigma0 = CryptoUtils.signEd25519(privateKey, serialNumber + did);

        System.out.println("=== Device simulé ===");
        System.out.println("serial_number=" + serialNumber);
        System.out.println("device_private_key_hex=" + HexFormat.of().formatHex(privateKey));
        System.out.println("public_key=" + publicKey);
        System.out.println("did=" + did);
        System.out.println("signature_sigma0=" + signatureSigma0);
        System.out.println();
        System.out.println("=== Variables Postman à copier ===");
        System.out.println("serial_number = " + serialNumber);
        System.out.println("device_private_key_hex = " + HexFormat.of().formatHex(privateKey));
        System.out.println("public_key = " + publicKey);
        System.out.println("did = " + did);
        System.out.println("signature_sigma0 = " + signatureSigma0);
        System.out.println();
        System.out.println("Après la requête First contact, signer le nonce avec :");
        System.out.println("./mvnw -DskipTests test-compile exec:java -Dexec.classpathScope=test -Dexec.mainClass=com.iotauth.iot_auth.tools.NonceSigner -Dexec.args=\"" + HexFormat.of().formatHex(privateKey) + " <NONCE_RECU>\"");
    }
}
