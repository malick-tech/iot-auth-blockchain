package com.iotauth.iot_auth.config;

import com.iotauth.iot_auth.domain.entity.AdminUser;
import com.iotauth.iot_auth.repository.AdminUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminBootstrap implements CommandLineRunner {

    private final AdminUserRepository adminUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Value("${iot.auth.admin.bootstrap-username:admin}")
    private String bootstrapUsername;

    @Value("${iot.auth.admin.bootstrap-password:}")
    private String bootstrapPassword;

    @Override
    public void run(String... args) {
        if (adminUserRepository.count() == 0) {
            if (bootstrapPassword == null || bootstrapPassword.length() < 12) {
                log.error("Aucun compte admin et aucun mot de passe de bootstrap valide : definir " +
                        "IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD (12 caracteres minimum) pour creer le compte initial.");
                return;
            }
            AdminUser admin = new AdminUser();
            admin.setUsername(bootstrapUsername);
            admin.setFullName(bootstrapUsername);
            admin.setPasswordHash(passwordEncoder.encode(bootstrapPassword));
            adminUserRepository.save(admin);
            log.warn("Aucun compte admin trouvé - compte '{}' créé avec iot.auth.admin.bootstrap-password. " +
                    "Changez ce mot de passe rapidement.", bootstrapUsername);
            return;
        }

        adminUserRepository.findAll().stream()
                .filter(admin -> admin.getFullName() == null || admin.getFullName().isBlank())
                .forEach(admin -> {
                    admin.setFullName(admin.getUsername());
                    adminUserRepository.save(admin);
                });
    }
}