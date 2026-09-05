package com.iotauth.iot_auth.util;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CryptoUtilsTest {

    @Test
    void validateDidFormat_shouldAcceptOfficialDidAlgoAppNamespace() {
        byte[] publicKeyBytes = new byte[32];
        new SecureRandom().nextBytes(publicKeyBytes);
        String publicKeyBase32 = CryptoUtils.encodeBase32(publicKeyBytes);
        String did = CryptoUtils.buildDid(publicKeyBase32, 1014L, "localnet");

        assertThat(did).startsWith("did:algo:custom:app:1014:");
        assertThat(CryptoUtils.validateDidFormat(did, publicKeyBase32, 1014L, "localnet")).isTrue();
    }

    @Test
    void signAndVerifyEd25519_shouldReturnTrueForValidSignature() {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);

        Ed25519PrivateKeyParameters privateKeyParameters = new Ed25519PrivateKeyParameters(privateKey, 0);
        byte[] publicKeyBytes = privateKeyParameters.generatePublicKey().getEncoded();
        String publicKeyBase32 = CryptoUtils.encodeBase32(publicKeyBytes);
        String message = "test-message";

        String signature = CryptoUtils.signEd25519(privateKey, message);

        assertThat(CryptoUtils.verifyEd25519(publicKeyBase32, message, signature)).isTrue();
    }

    @Test
    void verifyEd25519_withInvalidPublicKeyLength_shouldThrowInvalidSignatureException() {
        assertThatThrownBy(() -> CryptoUtils.verifyEd25519("ABC", "message", "Zm9vYmFy"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Clé publique Ed25519 invalide");
    }
}
