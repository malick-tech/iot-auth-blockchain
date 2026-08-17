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

    @Value("${iot.auth.admin.bootstrap-password:changeme123}")
    private String bootstrapPassword;

    @Override
    public void run(String... args) {
        if (adminUserRepository.count() == 0) {
            AdminUser admin = new AdminUser();
            admin.setUsername(bootstrapUsername);
            admin.setPasswordHash(passwordEncoder.encode(bootstrapPassword));
            adminUserRepository.save(admin);
            log.warn("Aucun compte admin trouvé - compte '{}' créé avec le mot de passe par défaut. " +
                    "Change-le rapidement ou définis iot.auth.admin.bootstrap-password.", bootstrapUsername);
        }
    }
}