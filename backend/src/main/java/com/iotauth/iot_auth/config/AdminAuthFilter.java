package com.iotauth.iot_auth.config;

import com.iotauth.iot_auth.service.AdminJwtService;
import com.iotauth.iot_auth.service.CurrentAdminHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Protege tous les endpoints /api/admin/** sauf la connexion admin.
 * Le username authentifie est stocke dans CurrentAdminHolder pour l'audit.
 */
@Component
@RequiredArgsConstructor
public class AdminAuthFilter extends OncePerRequestFilter {

    private static final String LOGIN_PATH = "/api/admin/auth/login";

    private final AdminJwtService adminJwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        boolean isProtectedAdminPath = path.startsWith("/api/admin/") && !path.equals(LOGIN_PATH);

        if (isProtectedAdminPath) {
            String header = request.getHeader("Authorization");
            String token = (header != null && header.startsWith("Bearer ")) ? header.substring(7) : null;

            if (token == null || !adminJwtService.isValid(token)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write(
                        "{\"error\":\"Unauthorized\",\"message\":\"Authentification administrateur requise\"}"
                );
                return;
            }

            CurrentAdminHolder.set(adminJwtService.extractUsername(token));
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            CurrentAdminHolder.clear();
        }
    }
}
