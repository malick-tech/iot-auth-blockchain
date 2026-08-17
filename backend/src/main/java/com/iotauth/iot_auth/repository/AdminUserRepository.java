package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.AdminUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdminUserRepository extends JpaRepository<AdminUser, Long> {
    Optional<AdminUser> findByUsernameAndActiveTrue(String username);
    boolean existsByUsername(String username);
}