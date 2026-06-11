package com.iotauth.iot_auth.domain.entity;

import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "devices",
        indexes = {
                @Index(name = "idx_devices_serial_number", columnList = "serial_number", unique = true),
                @Index(name = "idx_devices_did", columnList = "did", unique = true),
                @Index(name = "idx_devices_status", columnList = "status")
        }
)
@Data
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true)
    private String serialNumber;

    @Column(unique = true)
    private String macAddress;

    @Column(unique = true)
    private String did;

    @Column(unique = true, length = 128)
    private String publicKey;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private DeviceStatus status;

    private String algorandTxId;
    private String deviceType;
    private String location;
    private String logicalGroup;
    private String responsible;

    private LocalDateTime activatedAt;
    private LocalDateTime suspendedAt;
    private LocalDateTime revokedAt;
    private LocalDateTime lastSeenAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @Column(columnDefinition = "TEXT")
    private String suspensionReason;

    @Column(columnDefinition = "TEXT")
    private String revocationReason;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (status == null) {
            status = DeviceStatus.PENDING;
        }
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
