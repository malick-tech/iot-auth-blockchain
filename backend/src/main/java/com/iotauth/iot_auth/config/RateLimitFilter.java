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
        if (path.equals("/api/admin/auth/login")) return "admin-login";
        if (path.startsWith("/api/enrollment/")) return "enrollment";
        if (path.startsWith("/api/auth/")) return "auth";
        if (path.startsWith("/api/operational/")) return "operational";
        return null;
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}