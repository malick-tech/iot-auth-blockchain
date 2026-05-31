package com.iotauth.iot_auth.domain.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(
        name = "verifiable_credentials",
        indexes = {
                @Index(name = "idx_vc_vc_id", columnList = "vc_id", unique = true),
                @Index(name = "idx_vc_subject_did", columnList = "subject_did")
        }
)
@Data
public class VerifiableCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true)
    private String vcId;

    @Column(nullable = false)
    private String issuerDid;

    @Column(nullable = false)
    private String subjectDid;

    @Column(nullable = false)
    private LocalDateTime issuedAt;

    @Column(nullable = false)
    private LocalDateTime expirationDate;

    @ElementCollection
    @CollectionTable(name = "vc_permissions", joinColumns = @JoinColumn(name = "vc_id"))
    private List<String> permissions = new ArrayList<>();

    @Column(nullable = false, columnDefinition = "TEXT")
    private String rawCredential;
}
