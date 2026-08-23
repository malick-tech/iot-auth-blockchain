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
import java.security.SecureRandom;
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
        if (configuredSecret == null || configuredSecret.isBlank()) {
            byte[] random = new byte[64];
            new SecureRandom().nextBytes(random);
            this.signingKey = Keys.hmacShaKeyFor(random);
            log.warn("Aucun secret JWT admin fourni (iot.auth.admin.jwt-secret) - clé éphémère générée. " +
                    "Toutes les sessions admin seront invalidées au prochain redémarrage.");
        } else {
            this.signingKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(configuredSecret));
        }
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
