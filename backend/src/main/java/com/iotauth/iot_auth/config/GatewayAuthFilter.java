package com.iotauth.iot_auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
@Component
public class GatewayAuthFilter extends OncePerRequestFilter {

    private static final String CACHE_HIT_LOG_PATH = "/api/operational/log-cache-hit";
    private static final String HEADER_NAME = "X-Gateway-Secret";

    @Value("${iot.auth.gateway.shared-secret:}")
    private String sharedSecret;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod()) || !CACHE_HIT_LOG_PATH.equals(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        if (sharedSecret == null || sharedSecret.isBlank()) {
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