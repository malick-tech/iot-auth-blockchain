package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VcRepository extends JpaRepository<VerifiableCredential, Long> {

    Optional<VerifiableCredential> findByCredentialId(String credentialId);

    Optional<VerifiableCredential> findByVcHash(String vcHash);

    List<VerifiableCredential> findByDeviceDeviceId(String deviceId);

    List<VerifiableCredential> findByDeviceDeviceIdAndRevokedFalse(String deviceId);

    List<VerifiableCredential> findByRevokedTrue();

    List<VerifiableCredential> findByExpiresAtBeforeAndRevokedFalse(Instant instant);
}
