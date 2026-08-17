package com.iotauth.iot_auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimitService {

    private final StringRedisTemplate redisTemplate;

    @Value("${iot.auth.rate-limit.enabled:true}")
    private boolean enabled;

    @Value("${iot.auth.rate-limit.max-requests:20}")
    private long maxRequests;

    @Value("${iot.auth.rate-limit.window-seconds:60}")
    private long windowSeconds;

    @Value("${iot.auth.rate-limit.admin-login.max-requests:5}")
    private long adminLoginMaxRequests;

    @Value("${iot.auth.rate-limit.admin-login.window-seconds:60}")
    private long adminLoginWindowSeconds;

    /**
     * Fenêtre fixe : incrémente un compteur Redis par identifiant (IP) et
     * catégorie d'endpoint, expiration = taille de la fenêtre. Retourne
     * false si le quota de la fenêtre courante est dépassé.
     *
     * La catégorie "admin-login" a son propre seuil, volontairement plus
     * strict (5/min par défaut) : c'est une protection anti brute-force
     * sur le mot de passe admin, pas juste une limite de débit générique.
     */
    public boolean isAllowed(String category, String identifier) {
        if (!enabled) {
            return true;
        }

        long limit = "admin-login".equals(category) ? adminLoginMaxRequests : maxRequests;
        long window = "admin-login".equals(category) ? adminLoginWindowSeconds : windowSeconds;

        String key = "ratelimit:" + category + ":" + identifier;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redisTemplate.expire(key, Duration.ofSeconds(window));
        }
        boolean allowed = count == null || count <= limit;
        if (!allowed) {
            log.warn("Rate limit dépassé pour category={} identifier={} (count={})", category, identifier, count);
        }
        return allowed;
    }
}