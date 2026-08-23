package com.iotauth.iot_auth.domain.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "admin_users")
public class AdminUser {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "admin_users_seq")
    @SequenceGenerator(name = "admin_users_seq", sequenceName = "admin_users_seq", allocationSize = 1)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    private String fullName;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private boolean active = true;

    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }
}