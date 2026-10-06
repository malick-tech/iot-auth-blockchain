package com.iotauth.iot_auth.config;

import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.service.AuditLogService;
import com.iotauth.iot_auth.service.RateLimitService;
import com.iotauth.iot_auth.util.ClientIpResolver;
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
            String clientIp = ClientIpResolver.resolve(request);
            boolean fromGateway = ClientIpResolver.isFromTrustedProxy(request);
            if (!rateLimitService.isAllowed(category, clientIp, fromGateway)) {
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
        // Appel interne de la gateway, authentifié par secret partagé (GatewayAuthFilter) :
        // un quota par IP le pénaliserait à chaque décision HIT, donc proportionnellement
        // au trafic légitime (cf. I-1/I-2).
        if (path.equals("/api/v1/operational/log-cache-hit")) return null;
        if (path.equals("/api/v1/admin/auth/login")) return "admin-login";
        if (path.startsWith("/api/v1/enrollment/")) return "enrollment";
        if (path.startsWith("/api/v1/auth/")) return "auth";
        if (path.startsWith("/api/v1/operational/")) return "operational";
        return null;
    }
}
