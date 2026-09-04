package com.iotauth.iot_auth.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests complémentaires sur CryptoUtils, couvrant les méthodes non traitées
 * dans CryptoUtilsTest : hashVp, generateNonce, encodeBase32/decodeBase32,
 * extractDidSubjectPublicKey, deriveEd25519PublicKeyBytes.
 */
class CryptoUtilsExtendedTest {

    // ── generateNonce ────────────────────────────────────────────────────────

    @Test
    void generateNonce_shouldReturnNonBlankBase64UrlString() {
        String nonce = CryptoUtils.generateNonce();
        assertThat(nonce).isNotBlank();
        // Base64 URL sans padding : pas de '=' ni de '+' ni de '/'
        assertThat(nonce).doesNotContain("=", "+", "/");
    }

    @Test
    void generateNonce_shouldReturnUniqueValuesEachCall() {
        String n1 = CryptoUtils.generateNonce();
        String n2 = CryptoUtils.generateNonce();
        assertThat(n1).isNotEqualTo(n2);
    }

    // ── hashVp ───────────────────────────────────────────────────────────────

    @Test
    void hashVp_shouldReturnDeterministicBase64String() {
        String vp = "{\"type\":\"VerifiablePresentation\"}";
        String hash1 = CryptoUtils.hashVp(vp);
        String hash2 = CryptoUtils.hashVp(vp);
        assertThat(hash1).isEqualTo(hash2);
        // SHA-256 (32 bytes) encodé en Base64 standard = 44 chars avec padding ou 43 sans
        assertThat(hash1.length()).isBetween(43, 44);
    }

    @Test
    void hashVp_shouldProduceDifferentHashForDifferentInputs() {
        assertThat(CryptoUtils.hashVp("vpA")).isNotEqualTo(CryptoUtils.hashVp("vpB"));
    }

    // ── encodeBase32 / decodeBase32 ──────────────────────────────────────────

    @Test
    void encodeAndDecodeBase32_shouldBeInverseOperations() {
        byte[] original = new byte[32];
        new java.security.SecureRandom().nextBytes(original);

        String encoded = CryptoUtils.encodeBase32(original);
        byte[] decoded = CryptoUtils.decodeBase32(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void encodeBase32_shouldProduceUppercaseAlphanumericString() {
        byte[] data = new byte[]{0x00, 0x44, (byte)0xff, 0x10, 0x20};
        String encoded = CryptoUtils.encodeBase32(data);
        assertThat(encoded).matches("[A-Z2-7]+");
    }

    @Test
    void decodeBase32_withInvalidInput_shouldThrowException() {
        assertThatThrownBy(() -> CryptoUtils.decodeBase32("!!!"))
                .isInstanceOf(RuntimeException.class);
    }

    // ── deriveEd25519PublicKeyBytes ──────────────────────────────────────────

    @Test
    void deriveEd25519PublicKeyBytes_shouldReturn32Bytes() {
        byte[] privateKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        byte[] publicKey = CryptoUtils.deriveEd25519PublicKeyBytes(privateKey);
        assertThat(publicKey).hasSize(32);
    }

    @Test
    void deriveEd25519PublicKeyBytes_shouldBeDeterministic() {
        byte[] privateKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        byte[] pub1 = CryptoUtils.deriveEd25519PublicKeyBytes(privateKey);
        byte[] pub2 = CryptoUtils.deriveEd25519PublicKeyBytes(privateKey);
        assertThat(pub1).isEqualTo(pub2);
    }

    @Test
    void deriveEd25519PublicKeyBytes_withInvalidLength_shouldThrow() {
        assertThatThrownBy(() -> CryptoUtils.deriveEd25519PublicKeyBytes(new byte[16]))
                .isInstanceOf(RuntimeException.class);
    }

    // ── extractDidSubjectPublicKey ───────────────────────────────────────────

    @Test
    void extractDidSubjectPublicKey_shouldRoundtripWithBuildDid() {
        byte[] privateKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        byte[] publicKeyBytes = CryptoUtils.deriveEd25519PublicKeyBytes(privateKey);
        String publicKeyBase32 = CryptoUtils.encodeBase32(publicKeyBytes);

        String did = CryptoUtils.buildDid(publicKeyBase32, 1010L, "localnet");
        byte[] extracted = CryptoUtils.extractDidSubjectPublicKey(did);

        assertThat(extracted).isEqualTo(publicKeyBytes);
    }

    @Test
    void extractDidSubjectPublicKey_withBlankDid_shouldThrowIllegalArgumentException() {
        assertThatThrownBy(() -> CryptoUtils.extractDidSubjectPublicKey(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void extractDidSubjectPublicKey_withInvalidFormat_shouldThrowIllegalArgumentException() {
        assertThatThrownBy(() -> CryptoUtils.extractDidSubjectPublicKey("not:a:valid:did:format:extra:segment:here"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ── encodeHex / decodeHex ────────────────────────────────────────────────

    @Test
    void encodeAndDecodeHex_shouldBeInverseOperations() {
        byte[] data = new byte[]{0x0a, (byte)0xf0, 0x42};
        assertThat(CryptoUtils.decodeHex(CryptoUtils.encodeHex(data))).isEqualTo(data);
    }

    // ── validateDidFormat ────────────────────────────────────────────────────

    @Test
    void validateDidFormat_withTamperedPublicKey_shouldReturnFalse() {
        byte[] privateKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String publicKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(privateKey));
        String did = CryptoUtils.buildDid(publicKey, 1010L, "localnet");

        byte[] otherKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String otherPublicKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(otherKey));

        assertThat(CryptoUtils.validateDidFormat(did, otherPublicKey, 1010L, "localnet")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  "})
    void validateDidFormat_withBlankInputs_shouldReturnFalse(String blank) {
        assertThat(CryptoUtils.validateDidFormat(blank, "SOMEKEY", 1010L, "localnet")).isFalse();
        assertThat(CryptoUtils.validateDidFormat("did:algo:APP:1010:abc", blank, 1010L, "localnet")).isFalse();
    }
}
