package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.exception.RateLimitExceededException;
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

    /** Quota PAR DID (par minute par défaut) : voir requireAllowed(). */
    @Value("${iot.auth.rate-limit.max-requests:20}")
    private long maxRequests;

    /**
     * Quota PAR IP pour les endpoints IoT : simple garde-fou global. Derrière la
     * gateway, toutes les requêtes des dispositifs partagent l'adresse de la gateway :
     * ce plafond représente donc la capacité totale acceptée, pas une limite par appareil.
     */
    @Value("${iot.auth.rate-limit.ip-max-requests:600}")
    private long ipMaxRequests;

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
        long limit = "admin-login".equals(category) ? adminLoginMaxRequests : ipMaxRequests;
        long window = "admin-login".equals(category) ? adminLoginWindowSeconds : windowSeconds;
        return isAllowed(category, identifier, limit, window);
    }

    /**
     * Correctif I-2 : limitation PAR DID. Lève RateLimitExceededException (HTTP 429)
     * si ce DID dépasse son quota sur la fenêtre. Protège un dispositif donné d'un
     * martèlement sans pénaliser les autres dispositifs derrière la même gateway.
     */
    public void requireAllowed(String category, String did) {
        if (did == null || did.isBlank()) {
            return;
        }
        if (!isAllowed("did-" + category, did, maxRequests, windowSeconds)) {
            throw new RateLimitExceededException(
                    "Limite de requêtes dépassée pour ce dispositif, réessayez plus tard.");
        }
    }

    boolean isAllowed(String category, String identifier, long limit, long window) {
        if (!enabled) {
            return true;
        }

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
