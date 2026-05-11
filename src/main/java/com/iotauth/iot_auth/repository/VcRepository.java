package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

    public interface VcRepository extends JpaRepository<VerifiableCredential, Long> {

        Optional<VerifiableCredential> findByCredentialId(String credentialId);

        Optional<VerifiableCredential> findByVcHash(String vcHash);

        List<VerifiableCredential> findByDeviceDeviceId(String deviceId);

        List<VerifiableCredential> findByDeviceDeviceIdAndRevokedFalse(String deviceId);

        List<VerifiableCredential> findByRevokedTrue();

        List<VerifiableCredential> findByExpiresAtBeforeAndRevokedFalse(Instant instant);
    }