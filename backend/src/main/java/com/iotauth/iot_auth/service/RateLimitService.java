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
     * Plafond PAR IP pour un appelant interne de confiance (la gateway). Derrière elle, toute
     * la flotte partage la même adresse : ce plafond représente la capacité totale acceptée,
     * pas une limite par appareil. Les autres appelants (accès direct au backend) restent
     * soumis au quota strict {@code max-requests}.
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
     * false si le quota de la fenêtre courante est dépassé. Le plafond large
     * ({@code ip-max-requests}) ne s'applique qu'aux appels venant d'un proxy
     * interne de confiance ; un client direct reste limité à {@code max-requests}.
     *
     * La catégorie "admin-login" a son propre seuil, volontairement plus
     * strict (5/min par défaut) : c'est une protection anti brute-force
     * sur le mot de passe admin, pas juste une limite de débit générique.
     */
    public boolean isAllowed(String category, String identifier, boolean fromTrustedProxy) {
        long limit;
        if ("admin-login".equals(category)) {
            limit = adminLoginMaxRequests;
        } else {
            limit = fromTrustedProxy ? ipMaxRequests : maxRequests;
        }
        long window = "admin-login".equals(category) ? adminLoginWindowSeconds : windowSeconds;
        return isAllowed(category, identifier, limit, window);
    }

    /**
     * Limitation par couple (DID, IP source). Lève RateLimitExceededException (HTTP 429)
     * si ce couple dépasse son quota sur la fenêtre.
     *
     * Le DID est déclaré par l'appelant avant toute authentification : un quota par DID seul
     * permettrait à n'importe qui d'épuiser celui d'un capteur et de l'empêcher de renouveler
     * son JWT. Y ajouter l'IP source isole l'appelant direct. Limite résiduelle : un attaquant
     * qui passe par la gateway (MQTT sans authentification, hypothèse H3) partage l'IP de la
     * gateway et peut toujours consommer le quota d'un DID.
     */
    public void requireAllowed(String category, String did, String clientIp) {
        if (did == null || did.isBlank()) {
            return;
        }
        String identifier = did + "|" + (clientIp == null ? "unknown" : clientIp);
        if (!isAllowed("did-" + category, identifier, maxRequests, windowSeconds)) {
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
