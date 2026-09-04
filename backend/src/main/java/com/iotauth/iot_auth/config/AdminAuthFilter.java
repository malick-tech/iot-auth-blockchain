package com.iotauth.iot_auth.config;

import com.iotauth.iot_auth.service.AdminJwtService;
import com.iotauth.iot_auth.service.CurrentAdminHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Protège tous les endpoints /api/v1/admin/** sauf login et logout.
 *
 * Ce filtre accomplit deux rôles complémentaires :
 * 1. Valide le JWT Bearer admin (signature + expiration + blacklist Redis).
 * 2. Écrit un objet Authentication dans le SecurityContext Spring Security,
 *    ce qui permet à la couche .authorizeHttpRequests() de vérifier que la
 *    requête est bien authentifiée — sans dépendre uniquement de ce filtre
 *    comme seul mécanisme de protection.
 */
@Component
@RequiredArgsConstructor
public class AdminAuthFilter extends OncePerRequestFilter {

    private static final String LOGIN_PATH  = "/api/v1/admin/auth/login";
    private static final String LOGOUT_PATH = "/api/v1/admin/auth/logout";

    private final AdminJwtService adminJwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        boolean isProtectedAdminPath = path.startsWith("/api/v1/admin/")
                && !path.equals(LOGIN_PATH)
                && !path.equals(LOGOUT_PATH);

        if (isProtectedAdminPath) {
            String header = request.getHeader("Authorization");
            String token = (header != null && header.startsWith("Bearer ")) ? header.substring(7) : null;

            if (token == null || !adminJwtService.isValid(token)) {
                SecurityContextHolder.clearContext();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write(
                        "{\"error\":\"Unauthorized\",\"message\":\"Authentification administrateur requise\"}"
                );
                return;
            }

            String username = adminJwtService.extractUsername(token);
            CurrentAdminHolder.set(username);

            // Écrire l'authentification dans le SecurityContext pour que Spring Security
            // confirme le statut "authenticated" au niveau de .authorizeHttpRequests().
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            CurrentAdminHolder.clear();
            // Nettoyage du SecurityContext après la requête pour éviter toute
            // fuite entre requêtes sur des threads réutilisés.
            SecurityContextHolder.clearContext();
        }
    }
}
