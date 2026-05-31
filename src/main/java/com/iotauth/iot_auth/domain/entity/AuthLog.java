package com.iotauth.iot_auth.domain.entity;

import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.EventType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "auth_logs",
        indexes = {
                @Index(name = "idx_auth_logs_device_did", columnList = "device_did"),
                @Index(name = "idx_auth_logs_event_type", columnList = "event_type"),
                @Index(name = "idx_auth_logs_timestamp", columnList = "timestamp")
        }
)
@Data
public class AuthLog {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String deviceDid;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private EventType eventType;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Enumerated(EnumType.STRING)
    private ActorType actor;

    private Boolean success;
    private String sourceIp;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(columnDefinition = "TEXT")
    private String metadata;

    @PrePersist
    void onCreate() {
        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
    }
}
