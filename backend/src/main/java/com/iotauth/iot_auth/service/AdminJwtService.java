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
import java.util.Base64;
import java.util.Date;

@Slf4j
@Service
public class AdminJwtService {

    @Value("${iot.auth.admin.jwt-secret:}")
    private String configuredSecret;

    @Value("${iot.auth.admin.jwt-expiration-seconds:28800}")
    private long expirationSeconds;

    private SecretKey signingKey;

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
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey)
                .compact();
    }

    public String extractUsername(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

    public boolean isValid(String token) {
        try {
            Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public long getExpirationSeconds() {
        return expirationSeconds;
    }
}