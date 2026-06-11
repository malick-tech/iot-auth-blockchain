package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface VcRepository extends JpaRepository<VerifiableCredential, Long> {

    Optional<VerifiableCredential> findByVcId(String vcId);

    List<VerifiableCredential> findBySubjectDid(String subjectDid);

    List<VerifiableCredential> findByIssuerDid(String issuerDid);

    List<VerifiableCredential> findBySubjectDidAndExpirationDateAfter(String subjectDid, LocalDateTime now);

    boolean existsByVcId(String vcId);
}
