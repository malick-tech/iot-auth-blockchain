package com.iotauth.iot_auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RateLimitFilter rateLimitFilter;
    private final GatewayAuthFilter gatewayAuthFilter;
    private final AdminAuthFilter adminAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> {})
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Métriques applicatives
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        // Documentation OpenAPI / Swagger
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
                        // Endpoints IoT publics (protégés par rate-limit + cryptographie)
                        .requestMatchers("/api/v1/enrollment/**", "/api/v1/auth/**", "/api/v1/operational/**").permitAll()
                        // Login et logout admin : publics (le token est absent ou non valide à ce stade)
                        .requestMatchers("/api/v1/admin/auth/login", "/api/v1/admin/auth/logout").permitAll()
                        // Toutes les autres routes admin exigent ROLE_ADMIN positionné par AdminAuthFilter.
                        // Spring Security sert ici de garde-fou secondaire : même si AdminAuthFilter
                        // n'écrivait pas le SecurityContext, la requête serait bloquée avec un 403.
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().denyAll()
                )
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(gatewayAuthFilter, RateLimitFilter.class)
                .addFilterAfter(adminAuthFilter, GatewayAuthFilter.class);

        return http.build();
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> disableRateLimitServletRegistration(RateLimitFilter filter) {
        return disabledRegistration(filter);
    }

    @Bean
    public FilterRegistrationBean<GatewayAuthFilter> disableGatewayAuthServletRegistration(GatewayAuthFilter filter) {
        return disabledRegistration(filter);
    }

    @Bean
    public FilterRegistrationBean<AdminAuthFilter> disableAdminAuthServletRegistration(AdminAuthFilter filter) {
        return disabledRegistration(filter);
    }

    private static <T extends jakarta.servlet.Filter> FilterRegistrationBean<T> disabledRegistration(T filter) {
        FilterRegistrationBean<T> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
