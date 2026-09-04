package com.iotauth.iot_auth.config;

import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.service.AuditLogService;
import com.iotauth.iot_auth.service.RateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Mitigation du Déni de Service (Menace 5 du modèle STRIDE) : limite le
 * nombre de requêtes par IP sur les endpoints sensibles (enrôlement,
 * authentification, opérationnel). La Gateway absorbe déjà la majorité
 * du trafic en cache HIT ; ce filtre protège les chemins qui atteignent
 * effectivement Spring Boot (cache MISS, renouvellement, enrôlement).
 */
@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final AuditLogService auditLogService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String category = categoryFor(path);

        if (category != null) {
            String clientIp = resolveClientIp(request);
            if (!rateLimitService.isAllowed(category, clientIp)) {
                auditLogService.record(
                        EventType.ANOMALY_DETECTED,
                        null,
                        ActorType.SYSTEM,
                        false,
                        "Rate limit dépassé - catégorie=" + category + " path=" + path,
                        null,
                        clientIp
                );
                response.setStatus(429);
                response.setContentType("application/json");
                response.getWriter().write(
                        "{\"error\":\"Too Many Requests\",\"message\":\"Limite de requêtes dépassée, réessayez plus tard.\"}"
                );
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String categoryFor(String path) {
        if (path.equals("/api/v1/admin/auth/login")) return "admin-login";
        if (path.startsWith("/api/v1/enrollment/")) return "enrollment";
        if (path.startsWith("/api/v1/auth/")) return "auth";
        if (path.startsWith("/api/v1/operational/")) return "operational";
        return null;
    }

    private String resolveClientIp(HttpServletRequest request) {
        // Bug 7 fix : X-Forwarded-For est spoofable si aucun reverse proxy de confiance
        // ne se trouve devant le backend. On lit ce header uniquement si l'adresse
        // distante correspond à un loopback ou à un range privé (proxy interne),
        // ce qui est le cas dans Docker Compose (gateway → backend via réseau interne).
        // Dans tous les autres cas on utilise l'adresse de connexion TCP directe.
        String remoteAddr = request.getRemoteAddr();
        if (isTrustedProxy(remoteAddr)) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                // Prendre la première IP de la chaîne (client d'origine)
                return forwarded.split(",")[0].trim();
            }
        }
        return remoteAddr;
    }

    /**
     * Retourne true si l'adresse TCP directe est celle d'un proxy interne de confiance
     * (loopback 127.x, IPv6 loopback ::1, ou plages RFC-1918/RFC-4193 privées).
     * Dans Docker Compose, le gateway bridge appelle le backend sur le réseau interne
     * (172.x ou 192.168.x), ce qui correspond à ces plages.
     */
    private boolean isTrustedProxy(String remoteAddr) {
        if (remoteAddr == null) return false;
        return remoteAddr.equals("127.0.0.1")
                || remoteAddr.equals("::1")
                || remoteAddr.startsWith("10.")
                || remoteAddr.startsWith("172.")
                || remoteAddr.startsWith("192.168.");
    }
}