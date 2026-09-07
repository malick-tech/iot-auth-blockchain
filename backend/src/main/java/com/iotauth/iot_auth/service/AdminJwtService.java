package com.iotauth.iot_auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Service
public class AdminJwtService {

    @Value("${iot.auth.admin.jwt-secret:}")
    private String configuredSecret;

    @Value("${iot.auth.admin.jwt-expiration-seconds:28800}")
    private long expirationSeconds;

    private SecretKey signingKey;

    // RedisService est injecté par setter pour éviter une dépendance circulaire
    // (RedisService → AdminJwtService n'existe pas, mais on garde le pattern propre)
    private final RedisService redisService;

    public AdminJwtService(RedisService redisService) {
        this.redisService = redisService;
    }

    @PostConstruct
    public void init() {
        String effectiveSecret = configuredSecret == null ? "" : configuredSecret.trim();
        byte[] keyBytes;

        try {
            keyBytes = Base64.getDecoder().decode(effectiveSecret);
        } catch (IllegalArgumentException ex) {
            keyBytes = effectiveSecret.getBytes(StandardCharsets.UTF_8);
        }

        boolean isDevelopmentLikeProfile = isDevelopmentLikeProfile();

        if (effectiveSecret.isBlank() || keyBytes.length < 64) {
            if (isDevelopmentLikeProfile) {
                log.warn("Secret JWT admin absent ou trop court pour le profil local; utilisation d'un secret de dev local pour eviter le blocage du contexte.");
                keyBytes = Base64.getDecoder().decode("ZGV2LWFkbWluLWp3dC1zZWNyZXQtZGV2LWFkbWluLWp3dC1zZWNyZXQtZGV2LWFkbWluLWp3dC1zZWNyZXQtMTIzNDU2Nzg5MA==");
            } else {
                log.error("======================================================================");
                log.error("ERREUR DE CONFIGURATION : iot.auth.admin.jwt-secret est absent ou trop court.");
                log.error("Toutes les sessions admin seraient invalidees au prochain redemarrage.");
                log.error("Definir IOT_AUTH_ADMIN_JWT_SECRET en variable d'environnement.");
                log.error("Pour generer une cle : openssl rand -base64 64");
                log.error("======================================================================");
                throw new IllegalStateException(
                    "Le secret JWT admin (IOT_AUTH_ADMIN_JWT_SECRET) est absent ou trop court. " +
                    "Le serveur refuse de demarrer sans un secret persistant afin d'eviter " +
                    "l'invalidation de toutes les sessions admin existantes. " +
                    "Consultez les logs pour les instructions de generation."
                );
            }
        }

        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private boolean isDevelopmentLikeProfile() {
        String activeProfiles = System.getProperty("spring.profiles.active", "");
        if (activeProfiles.isBlank()) {
            activeProfiles = System.getenv().getOrDefault("SPRING_PROFILES_ACTIVE", "");
        }
        return activeProfiles.contains("dev") || activeProfiles.contains("test") || activeProfiles.contains("local");
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationSeconds * 1000);

        return Jwts.builder()
                .subject(username)
                // jti unique pour permettre la blacklist ciblée au logout
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey)
                .compact();
    }

    public String extractUsername(String token) {
        Claims claims = parseClaims(token);
        return claims.getSubject();
    }

    /**
     * Extrait le JTI (JWT ID) d'un token pour pouvoir le blacklister.
     */
    public String extractJti(String token) {
        return parseClaims(token).getId();
    }

    /**
     * Retourne le TTL restant du token en secondes (utile pour calculer
     * la durée de blacklist dans Redis : pas besoin de garder plus longtemps).
     */
    public long extractRemainingTtlSeconds(String token) {
        Claims claims = parseClaims(token);
        long expMs = claims.getExpiration().getTime();
        long remaining = (expMs - Instant.now().toEpochMilli()) / 1000;
        return Math.max(remaining, 0);
    }

    /**
     * Valide un token : signature correcte + non expiré + non blacklisté (logout).
     */
    public boolean isValid(String token) {
        try {
            Claims claims = Jwts.parser().verifyWith(signingKey).build()
                    .parseSignedClaims(token).getPayload();
            // Bug 15 fix : vérification de la blacklist Redis pour les tokens révoqués au logout
            String jti = claims.getId();
            if (jti != null && redisService.isJwtBlacklisted(jti)) {
                return false;
            }
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Blackliste un token dans Redis jusqu'à son expiration naturelle.
     * Appelé lors du logout admin pour invalider immédiatement la session côté serveur.
     */
    public void blacklist(String token) {
        try {
            String jti = extractJti(token);
            long ttl = extractRemainingTtlSeconds(token);
            if (jti != null && ttl > 0) {
                redisService.blacklistJwtToken(jti, ttl);
            }
        } catch (Exception e) {
            log.warn("Impossible de blacklister le token admin : {}", e.getMessage());
        }
    }

    public long getExpirationSeconds() {
        return expirationSeconds;
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
