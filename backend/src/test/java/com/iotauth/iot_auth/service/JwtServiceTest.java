package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.exception.InvalidSignatureException;
import com.iotauth.iot_auth.util.CryptoUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtServiceTest {

    private static final String DID = "did:algo:ABC";
    private static final String ADMIN_DID = "did:algo:ADMIN";

    private AdminKeyService adminKeyService;
    private RedisService redisService;
    private JwtService service;

    // Clé admin réelle pour tester les vrais JWT EdDSA
    private byte[] adminPrivateKey;
    private String adminPublicKeyBase32;

    @BeforeEach
    void setUp() {
        adminPrivateKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        adminPublicKeyBase32 = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(adminPrivateKey));

        adminKeyService = mock(AdminKeyService.class);
        redisService = mock(RedisService.class);

        when(adminKeyService.getAdminDid()).thenReturn(ADMIN_DID);
        when(adminKeyService.getPublicKeyBase32()).thenReturn(adminPublicKeyBase32);
        when(adminKeyService.sign(anyString()))
                .thenAnswer(inv -> CryptoUtils.signEd25519(adminPrivateKey, inv.getArgument(0)));

        service = new JwtService(adminKeyService, redisService);
        ReflectionTestUtils.setField(service, "jwtTtlSeconds", 3600L);
    }

    // ── generateJwtPop ───────────────────────────────────────────────────────

    @Test
    void generateJwtPop_shouldReturnWellFormedResponse() {
        byte[] deviceKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String devicePubKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(deviceKey));

        JwtPopResponse response = service.generateJwtPop(DID, devicePubKey);

        assertThat(response).isNotNull();
        assertThat(response.getJwt()).isNotBlank();
        assertThat(response.getJwt().split("\\.")).hasSize(3);
        assertThat(response.getDid()).isEqualTo(DID);
        assertThat(response.getExpiresIn()).isEqualTo(3600L);
        assertThat(response.getExpiresAt()).isNotNull();
    }

    @Test
    void generateJwtPop_shouldPersistJtiInRedis() {
        byte[] deviceKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String devicePubKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(deviceKey));

        service.generateJwtPop(DID, devicePubKey);

        // Vérifie que le JTI a bien été sauvegardé avec le bon TTL
        verify(redisService).saveLastDeviceJti(eq(DID), anyString(), eq(3600L));
    }

    // ── verifyJwtPop ─────────────────────────────────────────────────────────

    @Test
    void verifyJwtPop_withValidToken_shouldReturnClaims() {
        byte[] deviceKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String devicePubKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(deviceKey));

        JwtPopResponse generated = service.generateJwtPop(DID, devicePubKey);
        JwtService.JwtClaims claims = service.verifyJwtPop(generated.getJwt());

        assertThat(claims.getSub()).isEqualTo(DID);
        assertThat(claims.getIss()).isEqualTo(ADMIN_DID);
        assertThat(claims.getJti()).isNotBlank();
        assertThat(claims.getExp()).isGreaterThan(claims.getIat());
    }

    @Test
    void verifyJwtPop_withInvalidFormat_shouldThrowInvalidSignatureException() {
        assertThatThrownBy(() -> service.verifyJwtPop("not.a.valid.jwt.with.too.many.parts"))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("Format");
    }

    @Test
    void verifyJwtPop_withTamperedPayload_shouldThrowInvalidSignatureException() {
        byte[] deviceKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String devicePubKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(deviceKey));
        JwtPopResponse generated = service.generateJwtPop(DID, devicePubKey);

        String[] parts = generated.getJwt().split("\\.");
        // On modifie le payload (partie centrale) — la signature ne correspond plus
        String tampered = parts[0] + ".TAMPERED_PAYLOAD." + parts[2];

        assertThatThrownBy(() -> service.verifyJwtPop(tampered))
                .isInstanceOf(InvalidSignatureException.class);
    }

    @Test
    void verifyJwtPop_whenJtiBlacklisted_shouldThrowInvalidSignatureException() {
        byte[] deviceKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String devicePubKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(deviceKey));
        JwtPopResponse generated = service.generateJwtPop(DID, devicePubKey);

        // Simuler un JTI blacklisté (dispositif suspendu/révoqué)
        when(redisService.isDeviceJtiBlacklisted(anyString())).thenReturn(true);

        assertThatThrownBy(() -> service.verifyJwtPop(generated.getJwt()))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("révoqué");
    }

    @Test
    void verifyJwtPop_whenJtiNotBlacklisted_shouldSucceed() {
        byte[] deviceKey = CryptoUtils.generateEd25519PrivateKeyBytes();
        String devicePubKey = CryptoUtils.encodeBase32(CryptoUtils.deriveEd25519PublicKeyBytes(deviceKey));
        JwtPopResponse generated = service.generateJwtPop(DID, devicePubKey);

        when(redisService.isDeviceJtiBlacklisted(anyString())).thenReturn(false);

        JwtService.JwtClaims claims = service.verifyJwtPop(generated.getJwt());

        assertThat(claims.getSub()).isEqualTo(DID);
    }
}
