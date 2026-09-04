package com.iotauth.iot_auth.config;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Authenticates internal calls sent by the IoT gateway to audit cache-hit
 * decisions. Without this shared secret, a caller could forge cache-hit logs or
 * trigger anomaly workflows through /api/operational/log-cache-hit.
 */
@Slf4j
@Component
public class GatewayAuthFilter extends OncePerRequestFilter {

    private static final String CACHE_HIT_LOG_PATH = "/api/v1/operational/log-cache-hit";
    private static final String HEADER_NAME = "X-Gateway-Secret";

    @Value("${iot.auth.gateway.shared-secret:}")
    private String sharedSecret;

    @PostConstruct
    public void init() {
        if (sharedSecret == null || sharedSecret.isBlank()) {
            log.error("======================================================================");
            log.error("ERREUR DE CONFIGURATION : iot.auth.gateway.shared-secret est absent.");
            log.error("Le endpoint /api/operational/log-cache-hit serait totalement inaccessible.");
            log.error("Definir IOT_AUTH_GATEWAY_SHARED_SECRET en variable d'environnement.");
            log.error("Pour generer un secret : openssl rand -hex 32");
            log.error("======================================================================");
            throw new IllegalStateException(
                "Le secret partagé Gateway (IOT_AUTH_GATEWAY_SHARED_SECRET) est absent. " +
                "Consultez les logs pour les instructions de génération."
            );
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod()) || !CACHE_HIT_LOG_PATH.equals(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        if (sharedSecret == null || sharedSecret.isBlank()) {
            // Ne devrait pas arriver grâce au @PostConstruct fail-fast, mais défense en profondeur
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Gateway secret not configured\"}");
            return;
        }

        String providedSecret = request.getHeader(HEADER_NAME);
        if (!constantTimeEquals(sharedSecret, providedSecret)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized gateway call\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean constantTimeEquals(String expected, String actual) {
        if (actual == null) {
            return false;
        }
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] actualBytes = actual.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expectedBytes, actualBytes);
    }
}