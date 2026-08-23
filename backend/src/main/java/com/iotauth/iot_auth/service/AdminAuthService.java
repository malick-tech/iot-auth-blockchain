package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.AdminUser;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.dto.request.AdminLoginRequest;
import com.iotauth.iot_auth.dto.response.AdminLoginResponse;
import com.iotauth.iot_auth.exception.InvalidAdminCredentialsException;
import com.iotauth.iot_auth.repository.AdminUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuthService {

    private final AdminUserRepository adminUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AdminJwtService adminJwtService;
    private final AuditLogService auditLogService;

    public AdminLoginResponse login(AdminLoginRequest request) {
        AdminUser admin = adminUserRepository.findByUsernameAndActiveTrue(request.getUsername())
                .orElseThrow(() -> {
                    auditLogService.recordAdminAction(
                            EventType.ADMIN_LOGIN_FAILURE,
                            request.getUsername(),
                            false,
                            "Tentative de connexion admin avec un identifiant introuvable"
                    );
                    return new InvalidAdminCredentialsException();
                });

        if (!passwordEncoder.matches(request.getPassword(), admin.getPasswordHash())) {
            log.warn("Echec de connexion admin pour username={}", request.getUsername());
            auditLogService.recordAdminAction(
                    EventType.ADMIN_LOGIN_FAILURE,
                    request.getUsername(),
                    false,
                    "Mot de passe admin invalide"
            );
            throw new InvalidAdminCredentialsException();
        }

        String token = adminJwtService.generateToken(admin.getUsername());
        auditLogService.recordAdminAction(
                EventType.ADMIN_LOGIN_SUCCESS,
                admin.getUsername(),
                true,
                "Connexion admin réussie"
        );
        log.info("Connexion admin réussie pour username={}", admin.getUsername());

        return AdminLoginResponse.builder()
                .token(token)
                .username(admin.getUsername())
                .expiresIn(adminJwtService.getExpirationSeconds())
                .build();
    }

    /**
     * Invalide immédiatement le token JWT admin côté serveur (blacklist Redis).
     * Le token reste cryptographiquement valide mais sera rejeté par AdminJwtService.isValid().
     *
     * @param token le Bearer token extrait du header Authorization
     */
    public void logout(String token) {
        adminJwtService.blacklist(token);
        String username = null;
        try {
            username = adminJwtService.extractUsername(token);
        } catch (Exception ignored) {
            // Token peut être illisible si déjà expiré au moment du logout
        }
        auditLogService.recordAdminAction(
                EventType.ADMIN_LOGIN_SUCCESS, // pas d'EventType LOGOUT — on réutilise SUCCESS pour trace
                username,
                true,
                "Déconnexion admin - token invalidé en blacklist"
        );
        log.info("Token admin blacklisté pour username={}", username);
    }

    public void register(com.iotauth.iot_auth.dto.request.AdminRegisterRequest request) {
        if (adminUserRepository.existsByUsername(request.getUsername())) {
            throw new com.iotauth.iot_auth.exception.AdminAlreadyExistsException(request.getUsername());
        }

        com.iotauth.iot_auth.domain.entity.AdminUser admin = new com.iotauth.iot_auth.domain.entity.AdminUser();
        admin.setUsername(request.getUsername());
        admin.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        adminUserRepository.save(admin);

        auditLogService.recordAdminAction(
                EventType.ADMIN_ACCOUNT_CREATED,
                CurrentAdminHolder.get(),
                true,
                "Nouveau compte admin créé : " + request.getUsername()
        );
        log.info("Nouveau compte admin créé : {} (par {})", request.getUsername(), CurrentAdminHolder.get());
    }
}
